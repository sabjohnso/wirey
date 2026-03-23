#lang racket/base

(require wirey/syntax)

(provide (all-defined-out))

;; ============================================================
;; UDP Header — 8 bytes
;; All fields big-endian (network byte order).
;; ============================================================

(define-protocol udp-header
  #:byte-order big
  (src-port   uint 2)
  (dst-port   uint 2)
  (length     uint 2)
  (checksum   uint 2))
