#!/bin/bash

# 创建唯一临时文件用于进程间通信
exit_flag="/tmp/openssl_exit_flag.$$"
log_file="/tmp/openssl_log.$$"

# 清理旧文件
rm -f "$exit_flag" "$log_file"

# 启动4个并行进程
for i in {1..4}; do
    (
        while true; do
            # 检查退出标志
            if [ -f "$exit_flag" ]; then
                echo "process $i error, exit..."
                break
            fi

            # 重定向所有输出到日志文件
            {
                export OPENSSL_riscvcap="ZBA_ZBB_ZBC_ZBS_V_ZVBB_ZVBC_ZVKB_ZVKG_ZVKNED_ZVKNHA_ZVKNHB_ZVKSED_ZVKSH"
                openssl speed -evp sm3
                openssl speed -evp sm4
                openssl speed -evp aes-128-cbc
                openssl speed -evp aes-192-cbc
                openssl speed -evp aes-256-cbc
                openssl speed -evp aes-128-gcm
                openssl speed -evp aes-192-gcm
                openssl speed -evp aes-256-gcm
                openssl speed -evp aes-128-xts
                openssl speed -evp aes-256-xts
                openssl speed -evp sha256
                openssl speed -evp sha512
            } >> "$log_file" 2>&1

            if grep -q "cause:" "$log_file"; then
                echo "process $i error, exit..."
                touch "$exit_flag"
                break
            fi

            # 清空日志文件（避免文件过大）
            > "$log_file"
        done
    ) &
done

# 等待所有后台进程结束
wait

# 清理临时文件
rm -f "$exit_flag" "$log_file"
killall -9 openssl
killall -9 run_crypto_stress_test.sh
echo "all processes exited"
