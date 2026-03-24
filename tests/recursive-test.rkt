#lang racket/base

(require rackunit
         rackunit/spec
         racket/match
         racket/list
         wirey/syntax
         wirey/protocol)

;; -- Simple inner struct --
(struct/wire item
  #:byte-order big
  (tag uint 1)
  (val uint 2))

;; -- Outer struct with repeated inner structs --
(struct/wire item-list
  #:byte-order big
  (count uint 1)
  (items item #:repeat (field-ref count) #:struct))

(describe "repeated struct fields"
  (it "encodes a list of inner structs"
    (define item1 (item-encode #:tag 1 #:val 100))
    (define item2 (item-encode #:tag 2 #:val 200))
    (define bs (item-list-encode #:count 2 #:items (list item1 item2)))
    ;; count=2, then 2 × 3-byte items = 7 bytes total
    (check-equal? (bytes-length bs) 7)
    (check-equal? (bytes-ref bs 0) 2))

  (it "decodes a list of inner struct instances"
    (define bs (bytes 2  1 #x00 #x64  2 #x00 #xC8))
    (define v (item-list-decode bs))
    (check-equal? (item-list-count v) 2)
    (define items (item-list-items v))
    (check-equal? (length items) 2)
    (check-pred item? (first items))
    (check-equal? (item-tag (first items)) 1)
    (check-equal? (item-val (first items)) 100)
    (check-equal? (item-tag (second items)) 2)
    (check-equal? (item-val (second items)) 200))

  (it "handles zero-count"
    (define bs (bytes 0))
    (define v (item-list-decode bs))
    (check-equal? (item-list-count v) 0)
    (check-equal? (item-list-items v) '())))

;; -- Self-referencing: simple TLV --
;; A node has a tag byte, a count byte, and then count children (which are nodes)
;; Tag 0 = leaf (no children), tag 1 = branch (has children)

(struct/wire tlv-node
  #:byte-order big
  (tag   uint 1)
  (count uint 1)
  (children tlv-node #:repeat (field-ref count) #:struct))

(describe "self-referencing struct (recursive TLV)"
  (it "decodes a leaf node (no children)"
    (define bs (bytes 0 0))  ;; tag=0, count=0
    (define v (tlv-node-decode bs))
    (check-equal? (tlv-node-tag v) 0)
    (check-equal? (tlv-node-count v) 0)
    (check-equal? (tlv-node-children v) '()))

  (it "decodes a node with leaf children"
    ;; Parent: tag=1, count=2
    ;; Child 1: tag=0, count=0
    ;; Child 2: tag=0, count=0
    (define bs (bytes 1 2  0 0  0 0))
    (define v (tlv-node-decode bs))
    (check-equal? (tlv-node-tag v) 1)
    (check-equal? (tlv-node-count v) 2)
    (define kids (tlv-node-children v))
    (check-equal? (length kids) 2)
    (check-pred tlv-node? (first kids))
    (check-equal? (tlv-node-tag (first kids)) 0)
    (check-equal? (tlv-node-tag (second kids)) 0))

  (it "decodes nested recursive structure"
    ;; Root: tag=1, count=1
    ;;   Child: tag=1, count=1
    ;;     Grandchild: tag=0, count=0
    (define bs (bytes 1 1  1 1  0 0))
    (define v (tlv-node-decode bs))
    (check-equal? (tlv-node-tag v) 1)
    (define child (first (tlv-node-children v)))
    (check-equal? (tlv-node-tag child) 1)
    (define grandchild (first (tlv-node-children child)))
    (check-equal? (tlv-node-tag grandchild) 0)
    (check-equal? (tlv-node-children grandchild) '())))
