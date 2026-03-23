#lang racket/base

(require wirey/syntax)

(provide (all-defined-out))

;; ============================================================
;; NASDAQ ITCH 5.0 Protocol Messages
;; All fields are big-endian, byte-aligned, fixed-width.
;; ============================================================

;; System Event (type "S") — 12 bytes
(struct/wire itch-system-event
  #:byte-order big
  (message-type  alpha  1)
  (stock-locate  uint   2)
  (tracking      uint   2)
  (timestamp     uint   6)
  (event-code    alpha  1))

;; Add Order — No MPID (type "A") — 36 bytes
(struct/wire itch-add-order
  #:byte-order big
  (message-type  alpha  1)
  (stock-locate  uint   2)
  (tracking      uint   2)
  (timestamp     uint   6)
  (order-ref     uint   8)
  (buy-sell      alpha  1)
  (shares        uint   4)
  (stock         alpha  8)
  (price         uint   4))

;; Add Order — With MPID (type "F") — 40 bytes
(struct/wire itch-add-order-mpid
  #:byte-order big
  (message-type  alpha  1)
  (stock-locate  uint   2)
  (tracking      uint   2)
  (timestamp     uint   6)
  (order-ref     uint   8)
  (buy-sell      alpha  1)
  (shares        uint   4)
  (stock         alpha  8)
  (price         uint   4)
  (attribution   alpha  4))

;; Order Executed (type "E") — 31 bytes
(struct/wire itch-order-executed
  #:byte-order big
  (message-type  alpha  1)
  (stock-locate  uint   2)
  (tracking      uint   2)
  (timestamp     uint   6)
  (order-ref     uint   8)
  (exec-shares   uint   4)
  (match-number  uint   8))

;; Order Delete (type "D") — 19 bytes
(struct/wire itch-order-delete
  #:byte-order big
  (message-type  alpha  1)
  (stock-locate  uint   2)
  (tracking      uint   2)
  (timestamp     uint   6)
  (order-ref     uint   8))

;; Trade — Non-Cross (type "P") — 44 bytes
(struct/wire itch-trade
  #:byte-order big
  (message-type  alpha  1)
  (stock-locate  uint   2)
  (tracking      uint   2)
  (timestamp     uint   6)
  (order-ref     uint   8)
  (buy-sell      alpha  1)
  (shares        uint   4)
  (stock         alpha  8)
  (price         uint   4)
  (match-number  uint   8))
