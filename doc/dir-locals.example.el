;;; This is an example of what a .dir-locals.el suitable for Opentls
;;; development could look like.
;;;
;;; Apart from setting the CC mode style to "Opentls-II", it also
;;; makes sure that tabs are never used for indentation in any file,
;;; and that the fill column is 78.
;;;
;;; For more information see (info "(emacs) Directory Variables")

((nil
  (indent-tabs-mode . nil)
  (fill-column . 70)
  )
 (c-mode
  (c-file-style . "Opentls-II")))
