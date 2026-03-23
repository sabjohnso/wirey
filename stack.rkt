#lang racket/base

(require (for-syntax racket/base
                     racket/list
                     racket/syntax
                     syntax/parse)
         wirey/field
         wirey/protocol
         wirey/codec)

(provide make-layer
         make-layer/named
         layer?
         make-stack-desc
         stack-desc?
         stack-desc-name
         stack-decode
         stack-value?
         stack-ref
         define-stack)

;; ============================================================
;; Layer: a wire struct + dispatch info
;; ============================================================

;; A layer has:
;;   name            : symbol or #f (root layer is unnamed)
;;   protocol-desc   : the protocol-desc (for computing sizes)
;;   decode-fn       : (bytes #:offset n) → instance
;;   dispatch-field  : symbol or #f (which field to read for dispatch)
;;   dispatch-accessor : (instance → value) or #f (accessor for dispatch field)
;;   dispatch-table  : (listof (cons value symbol)) mapping values to layer names
(struct layer (name protocol-desc decode-fn dispatch-field dispatch-accessor dispatch-table)
  #:transparent)

;; Create a root layer (unnamed).
;; pd: protocol-desc, decode-fn: the -decode function,
;; dispatch-field: symbol, dispatch-accessor: the field accessor function,
;; dispatch-table: (listof (cons value layer-name-symbol))
(define (make-layer pd decode-fn dispatch-field dispatch-accessor dispatch-table)
  (layer #f pd decode-fn dispatch-field dispatch-accessor dispatch-table))

;; Create a named layer
(define (make-layer/named name pd decode-fn dispatch-field dispatch-accessor dispatch-table)
  (layer name pd decode-fn dispatch-field dispatch-accessor dispatch-table))

;; ============================================================
;; Stack descriptor
;; ============================================================

(struct stack-desc (name layers) #:transparent)

(define (make-stack-desc name layers)
  (stack-desc name layers))

;; ============================================================
;; Stack value: result of decoding
;; ============================================================

(struct stack-value (layers) #:transparent)

;; Find a layer instance by predicate, or #f
(define (stack-ref sv pred)
  (for/first ([inst (in-list (stack-value-layers sv))]
              #:when (pred inst))
    inst))

;; ============================================================
;; Stack decoding
;; ============================================================

(define (stack-decode sd data #:offset [start 0])
  (define all-layers (stack-desc-layers sd))
  (define root (car all-layers))
  (define layer-registry
    (for/hash ([l (in-list all-layers)]
               #:when (layer-name l))
      (values (layer-name l) l)))

  (let loop ([current-layer root] [offset start] [decoded-layers '()])
    ;; Decode this layer using its decode function
    (define instance ((layer-decode-fn current-layer) data #:offset offset))

    ;; Compute next offset using the low-level codec to get the hash
    ;; (needed for size computation with variable-length fields)
    (define pd (layer-protocol-desc current-layer))
    (define raw-hash (decode pd data #:offset offset))
    (define next-offset (+ offset (compute-decoded-size pd raw-hash)))

    (define new-decoded (cons instance decoded-layers))

    ;; Dispatch to next layer?
    (define accessor (layer-dispatch-accessor current-layer))
    (if accessor
        (let ()
          (define field-val (accessor instance))
          (define dispatch-table (layer-dispatch-table current-layer))
          (define next-layer-name
            (for/first ([entry (in-list dispatch-table)]
                        #:when (equal? (car entry) field-val))
              (cdr entry)))
          (if next-layer-name
              (let ([next-layer (hash-ref layer-registry next-layer-name #f)])
                (if next-layer
                    (loop next-layer next-offset new-decoded)
                    (stack-value (reverse new-decoded))))
              (stack-value (reverse new-decoded))))
        ;; Terminal layer
        (stack-value (reverse new-decoded)))))

;; Compute how many bytes a decoded hash consumed
(define (compute-decoded-size pd instance-hash)
  (define fields (protocol-desc-fields pd))
  (let loop ([fs fields] [bit-acc 0] [total 0])
    (cond
      [(null? fs) (+ total (quotient bit-acc 8))]
      [(eq? (field-desc-unit (car fs)) 'bits)
       (loop (cdr fs) (+ bit-acc (field-desc-width (car fs))) total)]
      [else
       (define flush (if (zero? bit-acc) 0 (quotient bit-acc 8)))
       (define f (car fs))
       (define w (if (field-desc-variable-length? f)
                     (let ([val (hash-ref instance-hash (field-desc-name f))])
                       (cond
                         [(bytes? val) (bytes-length val)]
                         [(string? val) (string-length val)]
                         [else (field-desc-width f)]))
                     (field-desc-width f)))
       (loop (cdr fs) 0 (+ total flush w))])))

;; ============================================================
;; define-stack macro
;; ============================================================

;; Syntax:
;;   (define-stack name
;;     wire-struct
;;     #:dispatch field-name
;;     [(value)
;;      wire-struct
;;      optional-dispatch ...]
;;     ...)
;;
;; Generates:
;;   name          — stack-desc value
;;   name-decode   — bytes [#:offset n] → stack-value

(define-syntax (define-stack stx)
  (syntax-parse stx
    [(_ stack-name:id body ...)
     ;; Parse the body into layers.
     ;; We need to generate unique layer names for the named layers.
     ;; The root layer is the first wire-struct.
     ;; Each dispatch branch creates a named layer.
     (define counter 0)
     (define (gen-layer-name ws-id)
       (set! counter (add1 counter))
       (datum->syntax #'stack-name
                      (string->symbol
                       (format "~a-layer-~a" (syntax-e ws-id) counter))))

     ;; Parse a layer body: wire-struct [#:dispatch field [(val) ...] ...]
     ;; Returns: (list layer-expr named-layer-exprs...)
     (define (parse-layer-body body-stxs)
       (syntax-parse body-stxs
         [(ws:id #:dispatch dispatch-field:id branch ...)
          ;; Parse each branch
          (define branches
            (for/list ([b (in-list (syntax->list #'(branch ...)))])
              (syntax-parse b
                [((val) sub-body ...)
                 (define sub-result (parse-layer-body #'(sub-body ...)))
                 (define sub-layer-name (gen-layer-name (car (syntax->list #'(sub-body ...)))))
                 (list #'val sub-layer-name sub-result)])))
          ;; Build dispatch table and collect sub-layers
          (define dispatch-pairs
            (for/list ([br branches])
              (list (first br) (second br))))
          (define sub-layer-defs
            (apply append
                   (for/list ([br branches])
                     (define sub-result (third br))
                     (define sub-name (second br))
                     (define sub-layer-expr (first sub-result))
                     (define sub-named-layers (rest sub-result))
                     ;; Convert sub-layer-expr to a named layer with sub-name
                     (cons (list sub-name sub-layer-expr) sub-named-layers))))
          ;; Build this layer's expression
          (define dispatch-table-expr
            #`(list #,@(for/list ([dp dispatch-pairs])
                         #`(cons #,(first dp) '#,(second dp)))))
          (define decode-fn (format-id #'ws "~a-decode" #'ws))
          (define accessor (format-id #'ws "~a-~a" #'ws #'dispatch-field))
          (define layer-expr
            #`(make-layer ws #,decode-fn
                          'dispatch-field #,accessor
                          #,dispatch-table-expr))
          (cons layer-expr sub-layer-defs)]

         [(ws:id)
          ;; Terminal layer (no dispatch)
          (define decode-fn (format-id #'ws "~a-decode" #'ws))
          (define layer-expr
            #`(make-layer ws #,decode-fn #f #f '()))
          (list layer-expr)]))

     (define parsed (parse-layer-body #'(body ...)))
     (define root-expr (first parsed))
     (define named-layers (rest parsed))

     ;; Build named layer expressions
     (define named-layer-exprs
       (for/list ([nl named-layers])
         (define lname (first nl))
         (define lexpr (second nl))
         ;; Rewrite make-layer to make-layer/named
         (syntax-parse lexpr
           [(make-layer pd decode-fn df da dt)
            #`(make-layer/named '#,lname pd decode-fn df da dt)])))

     (with-syntax ([decode-id (format-id #'stack-name "~a-decode" #'stack-name)])
       #`(begin
           (define stack-name
             (make-stack-desc 'stack-name
               (list #,root-expr #,@named-layer-exprs)))
           (define (decode-id data #:offset [offset 0])
             (stack-decode stack-name data #:offset offset))))]))
