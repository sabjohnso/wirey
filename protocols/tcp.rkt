#lang racket/base

(require wirey/syntax)

(provide (all-defined-out))

;; ============================================================
;; TCP Header — fixed 20-byte portion
;; Variable-length options (when data-offset > 5) deferred to v0.3.
;; All multi-byte fields are big-endian (network byte order).
;; ============================================================

(struct/wire tcp-header
  #:byte-order big
  (src-port     uint 2)
  (dst-port     uint 2)
  (seq-number   uint 4)
  (ack-number   uint 4)
  (data-offset  uint 4  #:unit bits)
  (reserved     uint 3  #:unit bits)
  (ns           uint 1  #:unit bits)
  (cwr          uint 1  #:unit bits)
  (ece          uint 1  #:unit bits)
  (urg          uint 1  #:unit bits)
  (ack          uint 1  #:unit bits)
  (psh          uint 1  #:unit bits)
  (rst          uint 1  #:unit bits)
  (syn          uint 1  #:unit bits)
  (fin          uint 1  #:unit bits)
  (window-size  uint 2)
  (checksum     uint 2)
  (urgent-ptr   uint 2))
