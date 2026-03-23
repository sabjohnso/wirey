#lang racket/base

(require rackunit
         rackunit/spec
         wirey/field
         wirey/protocol
         wirey/codec
         wirey/case-block)

;; ===== Data-driven case dispatch =====

(describe "make-case-block"
  (it "creates a case block"
    (define cb (make-case-block 'additional-info
                 (list (make-case-branch 24 (list (make-field-desc 'value 'uint 1 'big)))
                       (make-case-branch 25 (list (make-field-desc 'value 'uint 2 'big))))))
    (check-pred case-block? cb)
    (check-eq? (case-block-discriminator cb) 'additional-info)))

(describe "encode (case block)"
  (define cb (make-case-block 'tag
               (list (make-case-branch 1 (list (make-field-desc 'val 'uint 1 'big)))
                     (make-case-branch 2 (list (make-field-desc 'val 'uint 2 'big)))
                     (make-case-branch 3 (list (make-field-desc 'x 'uint 1 'big)
                                               (make-field-desc 'y 'uint 1 'big))))))
  (define p (make-protocol-desc 'msg (list (make-field-desc 'tag 'uint 1 'big) cb)))

  (it "encodes the matching branch (1-byte value)"
    (define bs (encode p (hasheq 'tag 1 'val #xAA)))
    (check-equal? bs (bytes 1 #xAA)))

  (it "encodes the matching branch (2-byte value)"
    (define bs (encode p (hasheq 'tag 2 'val #xBBCC)))
    (check-equal? bs (bytes 2 #xBB #xCC)))

  (it "encodes a branch with multiple fields"
    (define bs (encode p (hasheq 'tag 3 'x 10 'y 20)))
    (check-equal? bs (bytes 3 10 20))))

(describe "decode (case block)"
  (define cb (make-case-block 'tag
               (list (make-case-branch 1 (list (make-field-desc 'val 'uint 1 'big)))
                     (make-case-branch 2 (list (make-field-desc 'val 'uint 2 'big)))
                     (make-case-branch 3 (list (make-field-desc 'x 'uint 1 'big)
                                               (make-field-desc 'y 'uint 1 'big))))))
  (define p (make-protocol-desc 'msg (list (make-field-desc 'tag 'uint 1 'big) cb)))

  (it "decodes the matching branch"
    (define v (decode p (bytes 1 #xAA)))
    (check-equal? (hash-ref v 'tag) 1)
    (check-equal? (hash-ref v 'val) #xAA))

  (it "decodes a 2-byte branch"
    (define v (decode p (bytes 2 #xBB #xCC)))
    (check-equal? (hash-ref v 'val) #xBBCC))

  (it "decodes a multi-field branch"
    (define v (decode p (bytes 3 10 20)))
    (check-equal? (hash-ref v 'x) 10)
    (check-equal? (hash-ref v 'y) 20))

  (it "fields from non-matching branches return #f"
    (define v (decode p (bytes 1 #xAA)))
    ;; 'x and 'y are in branch 3, not active
    (check-equal? (hash-ref v 'x #f) #f)
    (check-equal? (hash-ref v 'y #f) #f)))

(describe "case block with predicate branches"
  (define cb (make-case-block 'info
               (list (make-case-branch (λ (v) (<= v 23))
                       (list))  ;; no extra fields — value is inline
                     (make-case-branch 24
                       (list (make-field-desc 'ext-val 'uint 1 'big)))
                     (make-case-branch 25
                       (list (make-field-desc 'ext-val 'uint 2 'big)))
                     (make-case-branch 26
                       (list (make-field-desc 'ext-val 'uint 4 'big))))))
  (define p (make-protocol-desc 'cbor-like
              (list (make-field-desc 'info 'uint 1 'big) cb)))

  (it "matches predicate branch (inline value)"
    (define v (decode p (bytes 5)))
    (check-equal? (hash-ref v 'info) 5)
    (check-equal? (hash-ref v 'ext-val #f) #f))

  (it "matches exact-value branch (1-byte ext)"
    (define v (decode p (bytes 24 #xFF)))
    (check-equal? (hash-ref v 'info) 24)
    (check-equal? (hash-ref v 'ext-val) #xFF))

  (it "matches exact-value branch (4-byte ext)"
    (define v (decode p (bytes 26 #xDE #xAD #xBE #xEF)))
    (check-equal? (hash-ref v 'ext-val) #xDEADBEEF))

  (it "round-trips through encode/decode"
    (define v1 (hasheq 'info 10))
    (check-equal? (hash-ref (decode p (encode p v1)) 'info) 10)

    (define v2 (hasheq 'info 24 'ext-val #x42))
    (check-equal? (decode p (encode p v2)) v2)

    (define v3 (hasheq 'info 26 'ext-val #xCAFEBABE))
    (check-equal? (decode p (encode p v3)) v3)))

(describe "fields after case block"
  (define cb (make-case-block 'tag
               (list (make-case-branch 1 (list (make-field-desc 'val 'uint 1 'big)))
                     (make-case-branch 2 (list (make-field-desc 'val 'uint 2 'big))))))
  (define p (make-protocol-desc 'msg
              (list (make-field-desc 'tag 'uint 1 'big)
                    cb
                    (make-field-desc 'tail 'uint 1 'big))))

  (it "correctly offsets fields after a 1-byte branch"
    (define v (decode p (bytes 1 #xAA #xFF)))
    (check-equal? (hash-ref v 'val) #xAA)
    (check-equal? (hash-ref v 'tail) #xFF))

  (it "correctly offsets fields after a 2-byte branch"
    (define v (decode p (bytes 2 #xBB #xCC #xFF)))
    (check-equal? (hash-ref v 'val) #xBBCC)
    (check-equal? (hash-ref v 'tail) #xFF)))
