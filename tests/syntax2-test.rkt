#lang racket/base

(require rackunit
         rackunit/spec
         racket/match
         racket/list
         wirey/syntax2
         wirey/ir
         wirey/ir-codec)

;; ============================================================
;; Basic struct/wire on the new IR
;; ============================================================

(struct/wire simple-msg
  #:byte-order big
  (tag  uint 1)
  (val  uint 2))

(describe "struct/wire (new IR): basic"
  (it "encodes"
    (define bs (simple-msg-encode #:tag #xAA #:val #x1234))
    (check-equal? bs (bytes #xAA #x12 #x34)))

  (it "decodes"
    (define v (simple-msg-decode (bytes #xAA #x12 #x34)))
    (check-equal? (simple-msg-tag v) #xAA)
    (check-equal? (simple-msg-val v) #x1234))

  (it "predicate"
    (check-pred simple-msg? (simple-msg-decode (bytes 1 0 0)))
    (check-false (simple-msg? 42)))

  (it "match"
    (match (simple-msg-decode (bytes #xBB #x56 #x78))
      [(simple-msg #:tag t #:val v)
       (check-equal? t #xBB)
       (check-equal? v #x5678)])))

;; ============================================================
;; Bitfields
;; ============================================================

(struct/wire bitfield-msg
  #:byte-order big
  (version uint 4 #:unit bits)
  (ihl     uint 4 #:unit bits)
  (total   uint 2))

(describe "struct/wire (new IR): bitfields"
  (it "encodes"
    (define bs (bitfield-msg-encode #:version 4 #:ihl 5 #:total 1500))
    (check-equal? bs (bytes #x45 #x05 #xDC)))

  (it "decodes"
    (define v (bitfield-msg-decode (bytes #x45 #x05 #xDC)))
    (check-equal? (bitfield-msg-version v) 4)
    (check-equal? (bitfield-msg-ihl v) 5)
    (check-equal? (bitfield-msg-total v) 1500))

  (it "round-trips"
    (define bs (bitfield-msg-encode #:version 4 #:ihl 5 #:total 1500))
    (define v (bitfield-msg-decode bs))
    (check-equal? (bitfield-msg-version v) 4)
    (check-equal? (bitfield-msg-total v) 1500)))

;; ============================================================
;; Case dispatch
;; ============================================================

(struct/wire case-msg
  #:byte-order big
  (tag uint 1)
  (#:case tag
    [(1) (val-u8  uint 1)]
    [(2) (val-u16 uint 2)]))

(describe "struct/wire (new IR): case dispatch"
  (it "encodes branch 1"
    (check-equal? (case-msg-encode #:tag 1 #:val-u8 #xAA)
                  (bytes 1 #xAA)))

  (it "encodes branch 2"
    (check-equal? (case-msg-encode #:tag 2 #:val-u16 #xBBCC)
                  (bytes 2 #xBB #xCC)))

  (it "decodes branch 1"
    (define v (case-msg-decode (bytes 1 #xAA)))
    (check-equal? (case-msg-tag v) 1)
    (check-equal? (case-msg-val-u8 v) #xAA))

  (it "decodes branch 2"
    (define v (case-msg-decode (bytes 2 #xBB #xCC)))
    (check-equal? (case-msg-val-u16 v) #xBBCC))

  (it "inactive branch returns #f"
    (define v (case-msg-decode (bytes 1 #xAA)))
    (check-equal? (case-msg-val-u16 v) #f))

  (it "match"
    (match (case-msg-decode (bytes 2 #x12 #x34))
      [(case-msg #:tag t #:val-u16 v)
       (check-equal? t 2)
       (check-equal? v #x1234)])))

;; ============================================================
;; Variable-length
;; ============================================================

(struct/wire varlen-msg
  #:byte-order big
  (len  uint 2)
  (data octets (field-ref len)))

(describe "struct/wire (new IR): variable-length"
  (it "encodes"
    (check-equal? (varlen-msg-encode #:len 3 #:data (bytes 1 2 3))
                  (bytes 0 3 1 2 3)))

  (it "decodes"
    (define v (varlen-msg-decode (bytes 0 3 1 2 3)))
    (check-equal? (varlen-msg-len v) 3)
    (check-equal? (varlen-msg-data v) (bytes 1 2 3))))

;; ============================================================
;; Padding
;; ============================================================

(struct/wire padded-msg
  #:byte-order big
  (tag uint 1)
  (pad padding 3)
  (val uint 4))

(describe "struct/wire (new IR): padding"
  (it "encodes with zeros"
    (define bs (padded-msg-encode #:tag #xAA #:val #xDEADBEEF))
    (check-equal? bs (bytes #xAA 0 0 0 #xDE #xAD #xBE #xEF)))

  (it "decodes without padding accessor"
    (define v (padded-msg-decode (bytes #xAA 0 0 0 #xDE #xAD #xBE #xEF)))
    (check-equal? (padded-msg-tag v) #xAA)
    (check-equal? (padded-msg-val v) #xDEADBEEF)))

;; ============================================================
;; Default values
;; ============================================================

(struct/wire default-msg
  #:byte-order big
  (version uint 1 #:default 4)
  (flags   uint 1 #:default 0)
  (data    uint 2))

(describe "struct/wire (new IR): defaults"
  (it "uses defaults when omitted"
    (define bs (default-msg-encode #:data #x1234))
    (check-equal? bs (bytes 4 0 #x12 #x34)))

  (it "overrides defaults"
    (define bs (default-msg-encode #:version 6 #:data #x1234))
    (check-equal? (bytes-ref bs 0) 6)))

;; ============================================================
;; Phase 3 Step 8: Inactive branch omission
;; ============================================================

(describe "struct/wire (new IR): inactive branch omission"
  (it "case branch fields default to #f and are excluded from encoding"
    ;; Only tag=1 branch fields get encoded
    (define bs (case-msg-encode #:tag 1 #:val-u8 #xAA))
    (check-equal? bs (bytes 1 #xAA))
    ;; val-u16 is #f (default for case branch), not encoded
    )

  (it "round-trip: decode → encode produces same bytes"
    (define bs1 (bytes 1 #xAA))
    (define h (ir-decode case-msg bs1))
    (define bs2 (ir-encode case-msg h))
    (check-equal? bs2 bs1))

  (it "round-trip for branch 2"
    (define bs1 (bytes 2 #xBB #xCC))
    (define h (ir-decode case-msg bs1))
    (define bs2 (ir-encode case-msg h))
    (check-equal? bs2 bs1)))

;; ============================================================
;; Phase 3 Step 9: Value-level encode/decode
;; ============================================================

;; A simple tagged format: tag determines interpretation
(define (tagged-racket->fields v)
  (cond
    [(and (integer? v) (>= v 0))
     (hasheq 'tag 1 'val-u8 v)]
    [(string? v)
     (hasheq 'tag 2 'val-u16 (char->integer (string-ref v 0)))]
    [else (error "cannot encode" v)]))

(define (tagged-fields->racket h)
  (case (hash-ref h 'tag)
    [(1) (hash-ref h 'val-u8)]
    [(2) (string (integer->char (hash-ref h 'val-u16)))]
    [else #f]))

(struct/wire tagged-value
  #:byte-order big
  #:encode tagged-racket->fields
  #:decode tagged-fields->racket
  (tag uint 1)
  (#:case tag
    [(1) (val-u8  uint 1)]
    [(2) (val-u16 uint 2)]))

(describe "struct/wire (new IR): value-level encode/decode"
  (it "encode-value: integer"
    (check-equal? (tagged-value-encode-value 42) (bytes 1 42)))

  (it "encode-value: string"
    (check-equal? (tagged-value-encode-value "A") (bytes 2 0 65)))

  (it "decode-value: integer"
    (check-equal? (tagged-value-decode-value (bytes 1 42)) 42))

  (it "decode-value: string"
    (check-equal? (tagged-value-decode-value (bytes 2 0 65)) "A"))

  (it "round-trip: Racket value → bytes → Racket value"
    (check-equal? (tagged-value-decode-value (tagged-value-encode-value 42)) 42)
    (check-equal? (tagged-value-decode-value (tagged-value-encode-value "A")) "A")))
