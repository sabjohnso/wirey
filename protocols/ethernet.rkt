#lang racket/base

(require wirey/syntax)

(provide (all-defined-out))

;; ============================================================
;; Ethernet Frame Header — 14 bytes
;; MAC addresses are raw octets; ethertype is big-endian.
;; ============================================================

(define-protocol ethernet-header
  #:byte-order big
  (dst-mac    octets 6)
  (src-mac    octets 6)
  (ethertype  uint   2))
