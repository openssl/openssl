#include "internal/quic_cc.h"
#include "internal/quic_types.h"
#include "internal/safe_math.h"

OSSL_SAFE_MATH_UNSIGNED(u64, uint64_t)

typedef struct ossl_cc_newreno_st {
    /* Dependencies. */
    OSSL_TIME   (*now_cb)(void *arg);
    void        *now_cb_arg;

    /* 'Constants' (which we allow to be configurable). */
    uint64_t    k_init_wnd, k_min_wnd;
    uint32_t    k_loss_reduction_factor_num, k_loss_reduction_factor_den;
    uint32_t    persistent_cong_thresh;

    /* State. */
    size_t      max_dgram_size;
    uint64_t    bytes_in_flight, cong_wnd, slow_start_thresh, bytes_acked;
    OSSL_TIME   cong_recovery_start_time;

    /* Unflushed state during multiple on-loss calls. */
    int         processing_loss; /* 1 if not flushed */
    OSSL_TIME   tx_time_of_last_loss;

    /* Diagnostic state. */
    int         in_congestion_recovery;
} OSSL_CC_NEWRENO;

#define MIN_MAX_INIT_WND_SIZE    14720  /* RFC 9002 s. 7.2 */

/* TODO(QUIC): Pacing support. */

static void newreno_set_max_dgram_size(OSSL_CC_NEWRENO *nr,
                                       size_t max_dgram_size);

static void newreno_reset(OSSL_CC_DATA *cc);

static OSSL_CC_DATA *newreno_new(OSSL_TIME (*now_cb)(void *arg),
                                 void *now_cb_arg)
{
    OSSL_CC_NEWRENO *nr;

    if ((nr = OPENSSL_zalloc(sizeof(*nr))) == NULL)
        return NULL;

    nr->now_cb          = now_cb;
    nr->now_cb_arg      = now_cb_arg;

    newreno_set_max_dgram_size(nr, QUIC_MIN_INITIAL_DGRAM_LEN);
    newreno_reset((OSSL_CC_DATA *)nr);

    return (OSSL_CC_DATA *)nr;
}

static void newreno_free(OSSL_CC_DATA *cc)
{
    OPENSSL_free(cc);
}

static void newreno_set_max_dgram_size(OSSL_CC_NEWRENO *nr,
                                       size_t max_dgram_size)
{
    size_t max_init_wnd;
    int is_reduced = (max_dgram_size < nr->max_dgram_size);

    nr->max_dgram_size = max_dgram_size;

    max_init_wnd = 2 * max_dgram_size;
    if (max_init_wnd < MIN_MAX_INIT_WND_SIZE)
        max_init_wnd = MIN_MAX_INIT_WND_SIZE;

    nr->k_init_wnd = 10 * max_dgram_size;
    if (nr->k_init_wnd > max_init_wnd)
        nr->k_init_wnd = max_init_wnd;

    nr->k_min_wnd = 2 * max_dgram_size;

    if (is_reduced)
        nr->cong_wnd = nr->k_init_wnd;
}

static void newreno_reset(OSSL_CC_DATA *cc)
{
    OSSL_CC_NEWRENO *nr = (OSSL_CC_NEWRENO *)cc;

    nr->k_loss_reduction_factor_num     = 1;
    nr->k_loss_reduction_factor_den     = 2;
    nr->persistent_cong_thresh          = 3;

    nr->cong_wnd                    = nr->k_init_wnd;
    nr->bytes_in_flight             = 0;
    nr->bytes_acked                 = 0;
    nr->slow_start_thresh           = UINT64_MAX;
    nr->cong_recovery_start_time    = ossl_time_zero();

    nr->processing_loss         = 0;
    nr->tx_time_of_last_loss    = ossl_time_zero();
    nr->in_congestion_recovery  = 0;
}

static int newreno_set_option_uint(OSSL_CC_DATA *cc, uint32_t option_id,
                                   uint64_t value)
{
    OSSL_CC_NEWRENO *nr = (OSSL_CC_NEWRENO *)cc;

    switch (option_id) {
    case OSSL_CC_OPTION_MAX_DGRAM_PAYLOAD_LEN:
        if (value > SIZE_MAX || value < QUIC_MIN_INITIAL_DGRAM_LEN)
            return 0;

        newreno_set_max_dgram_size(nr, (size_t)value);
        return 1;

    default:
        return 0;
    }
}

static int newreno_get_option_uint(OSSL_CC_DATA *cc, uint32_t option_id,
                                   uint64_t *value)
{
    OSSL_CC_NEWRENO *nr = (OSSL_CC_NEWRENO *)cc;

    switch (option_id) {
    case OSSL_CC_OPTION_MAX_DGRAM_PAYLOAD_LEN:
        *value = (uint64_t)nr->max_dgram_size;
        return 1;

    case OSSL_CC_OPTION_CUR_CWND_SIZE:
        *value = nr->cong_wnd;
        return 1;

    case OSSL_CC_OPTION_MIN_CWND_SIZE:
        *value = nr->k_min_wnd;
        return 1;

    case OSSL_CC_OPTION_CUR_BYTES_IN_FLIGHT:
        *value = nr->bytes_in_flight;
        return 1;

    case OSSL_CC_OPTION_CUR_STATE:
        if (nr->in_congestion_recovery)
            *value = 'R';
        else if (nr->cong_wnd < nr->slow_start_thresh)
            *value = 'S';
        else
            *value = 'A';
        return 1;

    default:
        return 0;
    }
}

static int newreno_in_cong_recovery(OSSL_CC_NEWRENO *nr, OSSL_TIME tx_time)
{
    return ossl_time_compare(tx_time, nr->cong_recovery_start_time) <= 0;
}

static void newreno_cong(OSSL_CC_NEWRENO *nr, OSSL_TIME tx_time)
{
    int err = 0;

    /* No reaction if already in a recovery period. */
    if (newreno_in_cong_recovery(nr, tx_time))
        return;

    /* Start a new recovery period. */
    nr->in_congestion_recovery = 1;
    nr->cong_recovery_start_time = nr->now_cb(nr->now_cb_arg);

    /* slow_start_thresh = cong_wnd * loss_reduction_factor */
    nr->slow_start_thresh
        = safe_muldiv_u64(nr->cong_wnd,
                          nr->k_loss_reduction_factor_num,
                          nr->k_loss_reduction_factor_den,
                          &err);

    if (err)
        nr->slow_start_thresh = UINT64_MAX;

    nr->cong_wnd = nr->slow_start_thresh;
    if (nr->cong_wnd < nr->k_min_wnd)
        nr->cong_wnd = nr->k_min_wnd;
}

static void newreno_flush(OSSL_CC_NEWRENO *nr, uint32_t flags)
{
    if (!nr->processing_loss)
        return;

    newreno_cong(nr, nr->tx_time_of_last_loss);

    if ((flags & OSSL_CC_LOST_FLAG_PERSISTENT_CONGESTION) != 0) {
        nr->cong_wnd                    = nr->k_min_wnd;
        nr->cong_recovery_start_time    = ossl_time_zero();
    }

    nr->processing_loss = 0;
}

static uint64_t newreno_get_tx_allowance(OSSL_CC_DATA *cc)
{
    OSSL_CC_NEWRENO *nr = (OSSL_CC_NEWRENO *)cc;

    if (nr->bytes_in_flight >= nr->cong_wnd)
        return 0;

    return nr->cong_wnd - nr->bytes_in_flight;
}

static OSSL_TIME newreno_get_wakeup_deadline(OSSL_CC_DATA *cc)
{
    /*
     * The NewReno congestion controller does not vary its state in time, only
     * in response to stimulus.
     */
    return ossl_time_infinite();
}

static int newreno_on_data_sent(OSSL_CC_DATA *cc, uint64_t num_bytes)
{
    OSSL_CC_NEWRENO *nr = (OSSL_CC_NEWRENO *)cc;

    nr->bytes_in_flight += num_bytes;
    return 1;
}

static int newreno_is_cong_limited(OSSL_CC_NEWRENO *nr)
{
    uint64_t wnd_rem;

    /* We are congestion-limited if we are already at the congestion window. */
    if (nr->bytes_in_flight >= nr->cong_wnd)
        return 1;

    wnd_rem = nr->cong_wnd - nr->bytes_in_flight;

    /*
     * Consider ourselves congestion-limited if less than three datagrams' worth
     * of congestion window remains to be spent, or if we are in slow start and
     * have consumed half of our window.
     */
    return (nr->cong_wnd < nr->slow_start_thresh && wnd_rem <= nr->cong_wnd / 2)
           || wnd_rem <= 3 * nr->max_dgram_size;
}

static int newreno_on_data_acked(OSSL_CC_DATA *cc,
                                 const OSSL_CC_ACK_INFO *info)
{
    OSSL_CC_NEWRENO *nr = (OSSL_CC_NEWRENO *)cc;

    /*
     * Packet has been acked. Firstly, remove it from the aggregate count of
     * bytes in flight.
     */
    nr->bytes_in_flight -= info->tx_size;

    /*
     * We use acknowledgement of data as a signal that we are not at channel
     * capacity and that it may be reasonable to increase the congestion window.
     * However, acknowledgement is not a useful signal that there is further
     * capacity if we are not actually saturating the congestion window that we
     * already have (for example, if the application is not generating much data
     * or we are limited by flow control). Therefore, we only expand the
     * congestion window if we are consuming a significant fraction of the
     * congestion window.
     */
    if (!newreno_is_cong_limited(nr))
        return 1;

    /*
     * We can handle acknowledgement of a packet in one of three ways
     * depending on our current state:
     *
     *   - Congestion Recovery: Do nothing. We don't start increasing
     *     the congestion window in response to acknowledgements until
     *     we are no longer in the Congestion Recovery state.
     *
     *   - Slow Start: Increase the congestion window using the slow
     *     start scale.
     *
     *   - Congestion Avoidance: Increase the congestion window using
     *     the congestion avoidance scale.
     */
    if (newreno_in_cong_recovery(nr, info->tx_time)) {
        /* Congestion recovery, do nothing. */
        return 1;
    } else if (nr->cong_wnd < nr->slow_start_thresh) {
        /* When this condition is true we are in the Slow Start state. */
        nr->cong_wnd += info->tx_size;
        nr->in_congestion_recovery = 0;
        return 1;
    } else {
        /* Otherwise, we are in the Congestion Avoidance state. */
        nr->bytes_acked += info->tx_size;

        /*
         * Avoid integer division as per RFC 9002 s. B.5. / RFC3465 s. 2.1.
         */
        if (nr->bytes_acked >= nr->cong_wnd) {
            nr->bytes_acked -= nr->cong_wnd;
            nr->cong_wnd    += nr->max_dgram_size;
        }

        nr->in_congestion_recovery = 0;
        return 1;
    }
}

static int newreno_on_data_lost(OSSL_CC_DATA *cc,
                                const OSSL_CC_LOSS_INFO *info)
{
    OSSL_CC_NEWRENO *nr = (OSSL_CC_NEWRENO *)cc;

    if (info->tx_size > nr->bytes_in_flight)
        return 0;

    nr->bytes_in_flight -= info->tx_size;

    if (!nr->processing_loss) {

        if (ossl_time_compare(info->tx_time, nr->tx_time_of_last_loss) <= 0)
            /*
             * After triggering congestion due to a lost packet at time t, don't
             * trigger congestion again due to any subsequently detected lost
             * packet at a time s < t, as we've effectively already signalled
             * congestion on loss of that and subsequent packets.
             */
            return 1;

        nr->processing_loss = 1;

        /*
         * Cancel any pending window increase in the Congestion Avoidance state.
         */
        nr->bytes_acked = 0;
    }

    nr->tx_time_of_last_loss
        = ossl_time_max(nr->tx_time_of_last_loss, info->tx_time);
    return 1;
}

static int newreno_on_data_lost_finished(OSSL_CC_DATA *cc, uint32_t flags)
{
    OSSL_CC_NEWRENO *nr = (OSSL_CC_NEWRENO *)cc;

    newreno_flush(nr, flags);
    return 1;
}

static int newreno_on_data_invalidated(OSSL_CC_DATA *cc,
                                       uint64_t num_bytes)
{
    OSSL_CC_NEWRENO *nr = (OSSL_CC_NEWRENO *)cc;

    nr->bytes_in_flight -= num_bytes;
    return 1;
}

static int newreno_on_ecn(OSSL_CC_DATA *cc,
                          const OSSL_CC_ECN_INFO *info)
{
    OSSL_CC_NEWRENO *nr = (OSSL_CC_NEWRENO *)cc;

    nr->processing_loss         = 1;
    nr->bytes_acked             = 0;
    nr->tx_time_of_last_loss    = info->largest_acked_time;
    newreno_flush(nr, 0);
    return 1;
}

const OSSL_CC_METHOD ossl_cc_newreno_method = {
    newreno_new,
    newreno_free,
    newreno_reset,
    newreno_set_option_uint,
    newreno_get_option_uint,
    newreno_get_tx_allowance,
    newreno_get_wakeup_deadline,
    newreno_on_data_sent,
    newreno_on_data_acked,
    newreno_on_data_lost,
    newreno_on_data_lost_finished,
    newreno_on_data_invalidated,
    newreno_on_ecn,
};
