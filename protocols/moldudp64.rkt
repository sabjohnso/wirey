#lang racket/base

(require wirey/syntax)

(provide (all-defined-out))

;; ============================================================
;; MoldUDP64 Protocol (NASDAQ)
;;
;; MoldUDP64 is the transport protocol for ITCH data feeds.
;; Each UDP packet contains a MoldUDP64 header followed by
;; one or more message blocks, each with a 2-byte length prefix.
;; ============================================================

;; MoldUDP64 Packet Header — 20 bytes
;; Carried in UDP payload.
(struct/wire moldudp64-header
  #:byte-order big
  (session        alpha  10)
  (sequence-number uint   8)
  (message-count   uint   2))

;; MoldUDP64 Message Block Header — 2 bytes
;; Each message within the packet is prefixed with its length.
;; The message data follows immediately (length bytes).
(struct/wire moldudp64-message-block
  #:byte-order big
  (message-length uint 2)
  (message-data   octets (field-ref message-length)))
