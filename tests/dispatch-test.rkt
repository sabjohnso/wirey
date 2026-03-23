#lang racket/base

(require rackunit
         rackunit/spec
         racket/match
         wirey/syntax
         wirey/dispatch
         wirey/protocols/itch)

;; -- Simple test wire structs --

(struct/wire msg-a
  #:byte-order big
  (type alpha 1)
  (val  uint  2))

(struct/wire msg-b
  #:byte-order big
  (type alpha 1)
  (x    uint  1)
  (y    uint  1))

;; ===== Data-driven dispatch =====

(describe "make-dispatch-desc"
  (it "creates a dispatch descriptor"
    (define dd (make-dispatch-desc 'test-dispatch
                 #:offset 0 #:width 1 #:type 'alpha #:byte-order 'big
                 (list (cons "A" (list msg-a msg-a-decode msg-a?))
                       (cons "B" (list msg-b msg-b-decode msg-b?)))))
    (check-pred dispatch-desc? dd)
    (check-eq? (dispatch-desc-name dd) 'test-dispatch)))

(describe "dispatch-decode"
  (define dd (make-dispatch-desc 'test-dispatch
               #:offset 0 #:width 1 #:type 'alpha #:byte-order 'big
               (list (cons "A" (list msg-a msg-a-decode msg-a?))
                     (cons "B" (list msg-b msg-b-decode msg-b?)))))

  (it "dispatches to msg-a"
    (define bs (msg-a-encode #:type "A" #:val 42))
    (define result (dispatch-decode dd bs))
    (check-pred msg-a? result)
    (check-equal? (msg-a-type result) "A")
    (check-equal? (msg-a-val result) 42))

  (it "dispatches to msg-b"
    (define bs (msg-b-encode #:type "B" #:x 10 #:y 20))
    (define result (dispatch-decode dd bs))
    (check-pred msg-b? result)
    (check-equal? (msg-b-x result) 10)
    (check-equal? (msg-b-y result) 20))

  (it "returns #f for unknown discriminator"
    (define bs (bytes (char->integer #\Z) 0 0))
    (check-false (dispatch-decode dd bs))))

;; ===== define-dispatch macro =====

(define-dispatch test-msg
  #:offset 0
  #:width  1
  #:type   alpha
  [("A") msg-a]
  [("B") msg-b])

(describe "define-dispatch macro"
  (it "creates a dispatch descriptor"
    (check-pred dispatch-desc? test-msg))

  (it "generates a decode function"
    (define bs (msg-a-encode #:type "A" #:val 99))
    (define result (test-msg-decode bs))
    (check-pred msg-a? result)
    (check-equal? (msg-a-val result) 99))

  (it "works with match on dispatched results"
    (define bs-a (msg-a-encode #:type "A" #:val 42))
    (define bs-b (msg-b-encode #:type "B" #:x 1 #:y 2))
    (match (test-msg-decode bs-a)
      [(msg-a #:val v) (check-equal? v 42)])
    (match (test-msg-decode bs-b)
      [(msg-b #:x x #:y y)
       (check-equal? x 1)
       (check-equal? y 2)])))

;; ===== ITCH dispatch =====

(define-dispatch itch-message
  #:offset 0
  #:width  1
  #:type   alpha
  [("S") itch-system-event]
  [("A") itch-add-order]
  [("F") itch-add-order-mpid]
  [("E") itch-order-executed]
  [("D") itch-order-delete]
  [("P") itch-trade])

(describe "ITCH message dispatch"
  (it "dispatches a system event"
    (define bs (itch-system-event-encode
                #:message-type "S"
                #:stock-locate 0
                #:tracking 0
                #:timestamp #x00000E4E1C00
                #:event-code "O"))
    (define msg (itch-message-decode bs))
    (check-pred itch-system-event? msg)
    (check-equal? (itch-system-event-event-code msg) "O"))

  (it "dispatches an add order"
    (define bs (itch-add-order-encode
                #:message-type "A"
                #:stock-locate 1
                #:tracking 0
                #:timestamp #x0000094F7A00
                #:order-ref 12345678
                #:buy-sell "B"
                #:shares 100
                #:stock "AAPL"
                #:price 1500000))
    (define msg (itch-message-decode bs))
    (check-pred itch-add-order? msg)
    (match msg
      [(itch-add-order #:stock sym #:shares s #:price p)
       (check-equal? sym "AAPL")
       (check-equal? s 100)
       (check-equal? p 1500000)]))

  (it "dispatches a trade"
    (define bs (itch-trade-encode
                #:message-type "P"
                #:stock-locate 42
                #:tracking 7
                #:timestamp #x0000094F7A00
                #:order-ref 99999
                #:buy-sell "S"
                #:shares 200
                #:stock "MSFT"
                #:price 3000000
                #:match-number 5555))
    (define msg (itch-message-decode bs))
    (check-pred itch-trade? msg)
    (match msg
      [(itch-trade #:stock sym #:price p)
       (check-equal? sym "MSFT")
       (check-equal? p 3000000)]))

  (it "returns #f for unknown message type"
    (define bs (bytes (char->integer #\Z) 0 0 0 0 0 0 0 0 0 0 0))
    (check-false (itch-message-decode bs))))
