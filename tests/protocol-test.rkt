#lang racket/base

(require rackunit
         rackunit/spec
         wirey/field
         wirey/protocol)

(define msg-type   (make-field-desc 'message-type  'alpha 1 'big))
(define stock-loc  (make-field-desc 'stock-locate  'uint  2 'big))
(define tracking   (make-field-desc 'tracking      'uint  2 'big))
(define timestamp  (make-field-desc 'timestamp     'uint  6 'big))
(define event-code (make-field-desc 'event-code    'alpha 1 'big))

(describe "make-protocol-desc"
  (context "given valid fields"
    (it "stores name and fields"
      (define p (make-protocol-desc 'system-event
                                    (list msg-type stock-loc tracking timestamp event-code)))
      (check-eq? (protocol-desc-name p) 'system-event)
      (check-equal? (length (protocol-desc-fields p)) 5))

    (it "accepts an empty field list"
      (check-not-exn
       (λ () (make-protocol-desc 'empty '())))))

  (context "given invalid arguments"
    (it "rejects non-symbol name"
      (check-exn exn:fail?
        (λ () (make-protocol-desc "bad" (list msg-type)))))

    (it "rejects non-list fields"
      (check-exn exn:fail?
        (λ () (make-protocol-desc 'bad msg-type))))

    (it "rejects list containing non-field-desc"
      (check-exn exn:fail?
        (λ () (make-protocol-desc 'bad (list 'not-a-field)))))))

(describe "protocol-desc-total-size"
  (it "computes the sum of field widths"
    (define p (make-protocol-desc 'system-event
                                  (list msg-type stock-loc tracking timestamp event-code)))
    (check-equal? (protocol-desc-total-size p) 12))

  (it "returns 0 for empty protocol"
    (define p (make-protocol-desc 'empty '()))
    (check-equal? (protocol-desc-total-size p) 0)))

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
