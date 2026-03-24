#lang racket/base

(require wirey/syntax)

(provide (all-defined-out))

;; ============================================================
;; NASDAQ TotalView-ITCH 5.0 Protocol Messages
;; All fields are big-endian, byte-aligned, fixed-width.
;; Prices are unsigned integers with 4 implied decimal places.
;; Timestamps are nanoseconds since midnight.
;; ============================================================

;; --- System and Reference Data ---

;; System Event (type "S") — 12 bytes
(struct/wire itch-system-event
  #:byte-order big
  (message-type  alpha  1)
  (stock-locate  uint   2)
  (tracking      uint   2)
  (timestamp     uint   6)
  (event-code    alpha  1))

;; Stock Directory (type "R") — 39 bytes
(struct/wire itch-stock-directory
  #:byte-order big
  (message-type              alpha  1)
  (stock-locate              uint   2)
  (tracking                  uint   2)
  (timestamp                 uint   6)
  (stock                     alpha  8)
  (market-category           alpha  1)
  (financial-status          alpha  1)
  (round-lot-size            uint   4)
  (round-lots-only           alpha  1)
  (issue-classification      alpha  1)
  (issue-sub-type            alpha  2)
  (authenticity              alpha  1)
  (short-sale-threshold      alpha  1)
  (ipo-flag                  alpha  1)
  (luld-ref-price-tier       alpha  1)
  (etp-flag                  alpha  1)
  (etp-leverage-factor       uint   4)
  (inverse-indicator         alpha  1))

;; Stock Trading Action (type "H") — 25 bytes
(struct/wire itch-stock-trading-action
  #:byte-order big
  (message-type  alpha  1)
  (stock-locate  uint   2)
  (tracking      uint   2)
  (timestamp     uint   6)
  (stock         alpha  8)
  (trading-state alpha  1)
  (reserved      alpha  1)
  (reason        alpha  4))

;; Reg SHO Short Sale Price Test Restricted Indicator (type "Y") — 20 bytes
(struct/wire itch-reg-sho-restriction
  #:byte-order big
  (message-type    alpha  1)
  (stock-locate    uint   2)
  (tracking        uint   2)
  (timestamp       uint   6)
  (stock           alpha  8)
  (reg-sho-action  alpha  1))

;; Market Participant Position (type "L") — 26 bytes
(struct/wire itch-market-participant-position
  #:byte-order big
  (message-type       alpha  1)
  (stock-locate       uint   2)
  (tracking           uint   2)
  (timestamp          uint   6)
  (mpid               alpha  4)
  (stock              alpha  8)
  (primary-market-maker alpha  1)
  (market-maker-mode  alpha  1)
  (market-participant-state alpha  1))

;; MWCB Decline Level Message (type "V") — 35 bytes
(struct/wire itch-mwcb-decline-level
  #:byte-order big
  (message-type  alpha  1)
  (stock-locate  uint   2)
  (tracking      uint   2)
  (timestamp     uint   6)
  (level-1       uint   8)
  (level-2       uint   8)
  (level-3       uint   8))

;; MWCB Status Message (type "W") — 12 bytes
(struct/wire itch-mwcb-status
  #:byte-order big
  (message-type    alpha  1)
  (stock-locate    uint   2)
  (tracking        uint   2)
  (timestamp       uint   6)
  (breached-level  alpha  1))

;; IPO Quoting Period Update (type "K") — 28 bytes
(struct/wire itch-ipo-quoting-period-update
  #:byte-order big
  (message-type       alpha  1)
  (stock-locate       uint   2)
  (tracking           uint   2)
  (timestamp          uint   6)
  (stock              alpha  8)
  (ipo-quotation-release-time uint 4)
  (ipo-quotation-release-qualifier alpha 1)
  (ipo-price          uint   4))

;; LULD Auction Collar (type "J") — 35 bytes
(struct/wire itch-luld-auction-collar
  #:byte-order big
  (message-type         alpha  1)
  (stock-locate         uint   2)
  (tracking             uint   2)
  (timestamp            uint   6)
  (stock                alpha  8)
  (auction-collar-ref-price uint  4)
  (upper-auction-collar-price uint  4)
  (lower-auction-collar-price uint  4)
  (auction-collar-extension uint  4))

;; Operational Halt (type "h") — 21 bytes
(struct/wire itch-operational-halt
  #:byte-order big
  (message-type     alpha  1)
  (stock-locate     uint   2)
  (tracking         uint   2)
  (timestamp        uint   6)
  (stock            alpha  8)
  (market-code      alpha  1)
  (operational-halt-action alpha  1))

;; --- Order Messages ---

;; Add Order — No MPID Attribution (type "A") — 36 bytes
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

;; Add Order — With MPID Attribution (type "F") — 40 bytes
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

;; Order Executed With Price (type "C") — 36 bytes
(struct/wire itch-order-executed-price
  #:byte-order big
  (message-type  alpha  1)
  (stock-locate  uint   2)
  (tracking      uint   2)
  (timestamp     uint   6)
  (order-ref     uint   8)
  (exec-shares   uint   4)
  (match-number  uint   8)
  (printable     alpha  1)
  (exec-price    uint   4))

;; Order Cancel (type "X") — 23 bytes
(struct/wire itch-order-cancel
  #:byte-order big
  (message-type     alpha  1)
  (stock-locate     uint   2)
  (tracking         uint   2)
  (timestamp        uint   6)
  (order-ref        uint   8)
  (cancelled-shares uint   4))

;; Order Delete (type "D") — 19 bytes
(struct/wire itch-order-delete
  #:byte-order big
  (message-type  alpha  1)
  (stock-locate  uint   2)
  (tracking      uint   2)
  (timestamp     uint   6)
  (order-ref     uint   8))

;; Order Replace (type "U") — 35 bytes
(struct/wire itch-order-replace
  #:byte-order big
  (message-type         alpha  1)
  (stock-locate         uint   2)
  (tracking             uint   2)
  (timestamp            uint   6)
  (original-order-ref   uint   8)
  (new-order-ref        uint   8)
  (shares               uint   4)
  (price                uint   4))

;; --- Trade Messages ---

;; Trade Message — Non-Cross (type "P") — 44 bytes
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

;; Cross Trade (type "Q") — 40 bytes
(struct/wire itch-cross-trade
  #:byte-order big
  (message-type    alpha  1)
  (stock-locate    uint   2)
  (tracking        uint   2)
  (timestamp       uint   6)
  (shares          uint   8)
  (stock           alpha  8)
  (cross-price     uint   4)
  (match-number    uint   8)
  (cross-type      alpha  1))

;; Broken Trade (type "B") — 19 bytes
(struct/wire itch-broken-trade
  #:byte-order big
  (message-type  alpha  1)
  (stock-locate  uint   2)
  (tracking      uint   2)
  (timestamp     uint   6)
  (match-number  uint   8))

;; --- Net Order Imbalance ---

;; NOII — Net Order Imbalance Indicator (type "I") — 50 bytes
(struct/wire itch-noii
  #:byte-order big
  (message-type           alpha  1)
  (stock-locate           uint   2)
  (tracking               uint   2)
  (timestamp              uint   6)
  (paired-shares          uint   8)
  (imbalance-shares       uint   8)
  (imbalance-direction    alpha  1)
  (stock                  alpha  8)
  (far-price              uint   4)
  (near-price             uint   4)
  (current-ref-price      uint   4)
  (cross-type             alpha  1)
  (price-variation        alpha  1))

;; Retail Price Improvement Indicator (type "N") — 20 bytes
(struct/wire itch-retail-price-improvement
  #:byte-order big
  (message-type  alpha  1)
  (stock-locate  uint   2)
  (tracking      uint   2)
  (timestamp     uint   6)
  (stock         alpha  8)
  (interest-flag alpha  1))

;; Direct Listing with Capital Raise Price Discovery (type "O") — 48 bytes
(struct/wire itch-direct-listing
  #:byte-order big
  (message-type                alpha  1)
  (stock-locate                uint   2)
  (tracking                    uint   2)
  (timestamp                   uint   6)
  (stock                       alpha  8)
  (open-eligibility-status     alpha  1)
  (minimum-allowable-price     uint   4)
  (maximum-allowable-price     uint   4)
  (near-execution-price        uint   4)
  (near-execution-time         uint   8)
  (lower-price-range-collar    uint   4)
  (upper-price-range-collar    uint   4))
