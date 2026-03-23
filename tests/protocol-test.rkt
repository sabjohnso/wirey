#lang racket/base

(require rackunit
         rackunit/spec
         wirey/field
         wirey/protocol
         wirey/length-expr)

(define msg-type   (make-field-desc 'message-type  'alpha 1 'big))
(define stock-loc  (make-field-desc 'stock-locate  'uint  2 'big))
(define tracking   (make-field-desc 'tracking      'uint  2 'big))
(define timestamp  (make-field-desc 'timestamp     'uint  6 'big))
(define event-code (make-field-desc 'event-code    'alpha 1 'big))

(describe "make-protocol-desc"
  (context "given valid byte-width fields"
    (it "stores name and fields"
      (define p (make-protocol-desc 'system-event
                                    (list msg-type stock-loc tracking timestamp event-code)))
      (check-eq? (protocol-desc-name p) 'system-event)
      (check-equal? (length (protocol-desc-fields p)) 5))

    (it "accepts an empty field list"
      (check-not-exn
       (λ () (make-protocol-desc 'empty '())))))

  (context "given valid bitfield groups"
    (it "accepts bitfields that sum to 8 bits"
      (check-not-exn
       (λ () (make-protocol-desc 'byte-pair
               (list (make-field-desc 'hi 'uint 4 'big #:unit 'bits)
                     (make-field-desc 'lo 'uint 4 'big #:unit 'bits))))))

    (it "accepts bitfields that sum to 16 bits"
      (check-not-exn
       (λ () (make-protocol-desc 'word-fields
               (list (make-field-desc 'flags  'uint 3  'big #:unit 'bits)
                     (make-field-desc 'offset 'uint 13 'big #:unit 'bits))))))

    (it "accepts mixed byte and bitfield groups"
      (check-not-exn
       (λ () (make-protocol-desc 'mixed
               (list (make-field-desc 'version 'uint 4 'big #:unit 'bits)
                     (make-field-desc 'ihl     'uint 4 'big #:unit 'bits)
                     (make-field-desc 'total   'uint 2 'big)))))))

  (context "given invalid bitfield groups"
    (it "rejects bitfields that don't sum to whole bytes"
      (check-exn exn:fail?
        (λ () (make-protocol-desc 'bad
                (list (make-field-desc 'a 'uint 3 'big #:unit 'bits)
                      (make-field-desc 'b 'uint 4 'big #:unit 'bits))))))

    (it "rejects a lone bitfield that isn't a whole byte"
      (check-exn exn:fail?
        (λ () (make-protocol-desc 'bad
                (list (make-field-desc 'a 'uint 5 'big #:unit 'bits))))))

    (it "rejects trailing bitfields that don't complete a byte"
      (check-exn exn:fail?
        (λ () (make-protocol-desc 'bad
                (list (make-field-desc 'x 'uint 2 'big)
                      (make-field-desc 'a 'uint 3 'big #:unit 'bits)))))))

  (context "given invalid arguments"
    (it "rejects non-symbol name"
      (check-exn exn:fail?
        (λ () (make-protocol-desc "bad" (list msg-type)))))

    (it "rejects non-list fields"
      (check-exn exn:fail?
        (λ () (make-protocol-desc 'bad msg-type))))

    (it "rejects list containing non-field-desc"
      (check-exn exn:fail?
        (λ () (make-protocol-desc 'bad (list 'not-a-field))))))

  (context "variable-length field validation"
    (it "accepts a field-ref referencing an earlier field"
      (check-not-exn
       (λ () (make-protocol-desc 'pkt
               (list (make-field-desc 'len  'uint 2 'big)
                     (make-field-desc 'data 'octets (make-field-ref 'len) 'big))))))

    (it "rejects a field-ref referencing a later field (forward ref)"
      (check-exn exn:fail?
        (λ () (make-protocol-desc 'bad
                (list (make-field-desc 'data 'octets (make-field-ref 'len) 'big)
                      (make-field-desc 'len  'uint 2 'big))))))

    (it "rejects a field-ref referencing a nonexistent field"
      (check-exn exn:fail?
        (λ () (make-protocol-desc 'bad
                (list (make-field-desc 'data 'octets (make-field-ref 'missing) 'big))))))

    (it "accepts a compute expression referencing earlier fields"
      (check-not-exn
       (λ () (make-protocol-desc 'ipv4
               (list (make-field-desc 'ihl     'uint 4 'big #:unit 'bits)
                     (make-field-desc 'version 'uint 4 'big #:unit 'bits)
                     (make-field-desc 'rest    'uint 18 'big)
                     (make-field-desc 'options 'octets
                                      (make-compute '(* (- (field-ref ihl) 5) 4)
                                                    (λ (lk) (* (- (lk 'ihl) 5) 4)))
                                      'big))))))))

(describe "protocol-desc-total-size"
  (it "computes the sum of field widths for byte fields"
    (define p (make-protocol-desc 'system-event
                                  (list msg-type stock-loc tracking timestamp event-code)))
    (check-equal? (protocol-desc-total-size p) 12))

  (it "returns 0 for empty protocol"
    (define p (make-protocol-desc 'empty '()))
    (check-equal? (protocol-desc-total-size p) 0))

  (it "accounts for bitfield groups in bytes"
    (define p (make-protocol-desc 'with-bits
                (list (make-field-desc 'version 'uint 4  'big #:unit 'bits)
                      (make-field-desc 'ihl     'uint 4  'big #:unit 'bits)
                      (make-field-desc 'total   'uint 2  'big))))
    (check-equal? (protocol-desc-total-size p) 3))

  (it "handles multiple bitfield groups"
    (define p (make-protocol-desc 'multi-bits
                (list (make-field-desc 'a 'uint 4 'big #:unit 'bits)
                      (make-field-desc 'b 'uint 4 'big #:unit 'bits)
                      (make-field-desc 'c 'uint 2 'big)
                      (make-field-desc 'd 'uint 3 'big #:unit 'bits)
                      (make-field-desc 'e 'uint 13 'big #:unit 'bits))))
    ;; 8 bits + 2 bytes + 16 bits = 1 + 2 + 2 = 5
    (check-equal? (protocol-desc-total-size p) 5))

  (it "returns fixed portion size when variable fields present"
    (define p (make-protocol-desc 'pkt
                (list (make-field-desc 'len  'uint 2 'big)
                      (make-field-desc 'data 'octets (make-field-ref 'len) 'big))))
    ;; Only the fixed 'len field counts
    (check-equal? (protocol-desc-total-size p) 2)))

(describe "protocol-desc-has-variable-fields?"
  (it "returns #f for all-fixed protocols"
    (define p (make-protocol-desc 'fixed
                (list (make-field-desc 'a 'uint 4 'big))))
    (check-false (protocol-desc-has-variable-fields? p)))

  (it "returns #t when variable-length fields present"
    (define p (make-protocol-desc 'var
                (list (make-field-desc 'len  'uint 2 'big)
                      (make-field-desc 'data 'octets (make-field-ref 'len) 'big))))
    (check-true (protocol-desc-has-variable-fields? p))))

(describe "protocol-desc-field-ref"
  (it "retrieves a field by name"
    (define p (make-protocol-desc 'system-event
                                  (list msg-type stock-loc tracking timestamp event-code)))
    (define f (protocol-desc-field-ref p 'timestamp))
    (check-eq? (field-desc-name f) 'timestamp)
    (check-equal? (field-desc-width f) 6))

  (it "returns #f for unknown field name"
    (define p (make-protocol-desc 'system-event
                                  (list msg-type stock-loc)))
    (check-false (protocol-desc-field-ref p 'nonexistent))))
