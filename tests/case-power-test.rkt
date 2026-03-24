#lang racket/base

(require rackunit
         rackunit/spec
         racket/list
         racket/match
         wirey/syntax
         wirey/protocol
         wirey/codec
         wirey/case-block
         wirey/length-expr)

;; ============================================================
;; Step 1: Variable-length fields inside #:case branches
;; ============================================================

(struct/wire varlen-case-msg
  #:byte-order big
  (tag uint 1)
  (len uint 2)
  (#:case tag
    [(1) (data octets (field-ref len))]
    [(2) (data octets (field-ref len))
         (extra uint 1)]))

(describe "variable-length fields in case branches"
  (it "encodes branch with field-ref width"
    (define bs (varlen-case-msg-encode #:tag 1 #:len 3 #:data (bytes 10 20 30)))
    (check-equal? bs (bytes 1 0 3 10 20 30)))

  (it "decodes branch with field-ref width"
    (define v (varlen-case-msg-decode (bytes 1 0 3 10 20 30)))
    (check-equal? (varlen-case-msg-tag v) 1)
    (check-equal? (varlen-case-msg-len v) 3)
    (check-equal? (varlen-case-msg-data v) (bytes 10 20 30)))

  (it "decodes second branch with extra field after var-len"
    (define v (varlen-case-msg-decode (bytes 2 0 2 #xAA #xBB #xFF)))
    (check-equal? (varlen-case-msg-tag v) 2)
    (check-equal? (varlen-case-msg-data v) (bytes #xAA #xBB))
    (check-equal? (varlen-case-msg-extra v) #xFF)))

;; ============================================================
;; Step 2: Cross-case field references
;; ============================================================

(struct/wire cross-case-msg
  #:byte-order big
  (info uint 1)
  (#:case info
    [((λ (v) (<= v 23)))]
    [(24) (argument uint 1)]
    [(25) (argument uint 2)]
    [(26) (argument uint 4)])
  (payload octets (compute (λ (lk) (or (lk 'argument) (lk 'info))))))

(describe "cross-case field references"
  (it "uses inline value when argument absent (info <= 23)"
    (define v (cross-case-msg-decode (bytes 5  10 20 30 40 50)))
    (check-equal? (cross-case-msg-info v) 5)
    (check-equal? (cross-case-msg-argument v) #f)
    (check-equal? (cross-case-msg-payload v) (bytes 10 20 30 40 50)))

  (it "uses explicit argument when present (info = 24)"
    (define v (cross-case-msg-decode (bytes 24 3  10 20 30)))
    (check-equal? (cross-case-msg-info v) 24)
    (check-equal? (cross-case-msg-argument v) 3)
    (check-equal? (cross-case-msg-payload v) (bytes 10 20 30)))

  (it "uses 2-byte argument (info = 25)"
    (define v (cross-case-msg-decode (bytes 25 0 4  10 20 30 40)))
    (check-equal? (cross-case-msg-argument v) 4)
    (check-equal? (cross-case-msg-payload v) (bytes 10 20 30 40))))

;; ============================================================
;; Step 3: Embedded #:struct in case branches
;; ============================================================

(struct/wire inner-val
  #:byte-order big
  (x uint 1)
  (y uint 1))

(struct/wire embedded-case-msg
  #:byte-order big
  (tag uint 1)
  (#:case tag
    [(1) (val uint 2)]
    [(2) (nested inner-val #:struct)]))

(describe "embedded #:struct in case branches"
  (it "decodes non-struct branch"
    (define v (embedded-case-msg-decode (bytes 1 #x00 #x42)))
    (check-equal? (embedded-case-msg-tag v) 1)
    (check-equal? (embedded-case-msg-val v) #x42))

  (it "decodes struct branch"
    (define v (embedded-case-msg-decode (bytes 2 #x0A #x14)))
    (check-equal? (embedded-case-msg-tag v) 2)
    (define n (embedded-case-msg-nested v))
    (check-pred inner-val? n)
    (check-equal? (inner-val-x n) #x0A)
    (check-equal? (inner-val-y n) #x14)))

;; ============================================================
;; Step 4: #:repeat #:struct in case branches
;; ============================================================

(struct/wire repeated-case-msg
  #:byte-order big
  (tag uint 1)
  (count uint 1)
  (#:case tag
    [(1) (items inner-val #:repeat (field-ref count) #:struct)]
    [(2) (data octets (field-ref count))]))

(describe "#:repeat #:struct in case branches"
  (it "decodes repeated structs"
    ;; tag=1, count=2, then two inner-val (2 bytes each)
    (define v (repeated-case-msg-decode (bytes 1 2  #x0A #x14  #x1E #x28)))
    (check-equal? (repeated-case-msg-tag v) 1)
    (check-equal? (repeated-case-msg-count v) 2)
    (define items (repeated-case-msg-items v))
    (check-equal? (length items) 2)
    (check-equal? (inner-val-x (first items)) #x0A)
    (check-equal? (inner-val-y (second items)) #x28))

  (it "decodes octets branch"
    (define v (repeated-case-msg-decode (bytes 2 3  #xAA #xBB #xCC)))
    (check-equal? (repeated-case-msg-data v) (bytes #xAA #xBB #xCC))))

;; ============================================================
;; Step 5: Self-referencing #:struct in case branches
;; ============================================================

(struct/wire recursive-item
  #:byte-order big
  (tag uint 1)
  (#:case tag
    [(0) (value uint 2)]
    [(1) (child recursive-item #:struct)]))

(describe "self-referencing #:struct in case branches"
  (it "decodes leaf (non-recursive branch)"
    (define v (recursive-item-decode (bytes 0 #x00 #x42)))
    (check-equal? (recursive-item-tag v) 0)
    (check-equal? (recursive-item-value v) #x42))

  (it "decodes one level of recursion"
    ;; tag=1 → child is recursive-item: tag=0, value=0x0042
    (define v (recursive-item-decode (bytes 1  0 #x00 #x42)))
    (check-equal? (recursive-item-tag v) 1)
    (define child (recursive-item-child v))
    (check-pred recursive-item? child)
    (check-equal? (recursive-item-tag child) 0)
    (check-equal? (recursive-item-value child) #x42))

  (it "decodes two levels of recursion"
    ;; tag=1 → child: tag=1 → child: tag=0, value=0x00FF
    (define v (recursive-item-decode (bytes 1  1  0 #x00 #xFF)))
    (define child (recursive-item-child v))
    (define grandchild (recursive-item-child child))
    (check-equal? (recursive-item-value grandchild) #xFF)))
