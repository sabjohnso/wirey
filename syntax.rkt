#lang racket/base

(require (for-syntax racket/base
                     racket/syntax
                     racket/list
                     syntax/parse)
         racket/match
         racket/list
         wirey/field
         wirey/protocol
         wirey/codec
         wirey/length-expr)

(provide struct/wire)

;; ============================================================
;; Runtime helpers for variable-length struct/wire instances
;; ============================================================

;; Compute field boundaries: returns a vector of (offset . width) pairs.
;; Used at decode time for protocols with variable-length fields.
(provide compute-field-boundaries)
(define (compute-field-boundaries pd data base-offset)
  (define fields (protocol-desc-fields pd))
  (define n (length fields))
  (define boundaries (make-vector n))
  (let loop ([fs fields] [byte-off base-offset] [bit-acc 0] [i 0] [decoded (hasheq)])
    (cond
      [(null? fs) boundaries]
      [(eq? (field-desc-unit (car fs)) 'bits)
       ;; Collect bitfield group (split on bit-order change)
       ;; Uses collect-bitfield-group from wirey/codec
       (define-values (group group-bits remaining)
         (collect-bitfield-group fs))
       (define group-bytes (quotient group-bits 8))
       (define bit-ord (resolve-group-bit-order group))
       ;; Read the group to decode bitfield values (needed for later field-ref lookups)
       (define raw
         (for/fold ([acc 0]) ([bi (in-range group-bytes)])
           (bitwise-ior (arithmetic-shift acc 8)
                        (bytes-ref data (+ byte-off bi)))))
       ;; Store boundaries and decode values for each field in group
       (let gloop ([gs group] [bit-pos 0] [gi i] [dec decoded])
         (if (null? gs)
             (loop remaining (+ byte-off group-bytes) 0 gi dec)
             (let* ([gf (car gs)]
                    [gw (field-desc-width gf)]
                    [val (case bit-ord
                           [(msb)
                            (define shift (- group-bits bit-pos gw))
                            (bitwise-and (arithmetic-shift raw (- shift))
                                         (sub1 (arithmetic-shift 1 gw)))]
                           [(lsb)
                            (bitwise-and (arithmetic-shift raw (- bit-pos))
                                         (sub1 (arithmetic-shift 1 gw)))])])
               ;; Store (group-byte-off group-bytes bit-pos bit-width bit-order)
               (vector-set! boundaries gi (list 'bits byte-off group-bytes bit-pos gw bit-ord))
               (gloop (cdr gs) (+ bit-pos gw) (+ gi 1)
                      (hash-set dec (field-desc-name gf) val)))))]
      [else
       (define f (car fs))
       ;; Check conditional presence
       (define pw (field-desc-present-when f))
       (cond
         [(and pw (not (pw (λ (name) (hash-ref decoded name)))))
          ;; Field absent — store marker, don't advance offset
          (vector-set! boundaries i (list 'absent))
          (loop (cdr fs) byte-off 0 (+ i 1)
                (hash-set decoded (field-desc-name f) #f))]
         [else
          (define w (if (field-desc-variable-length? f)
                        (eval-length-expr (field-desc-width f)
                                          (λ (name) (hash-ref decoded name)))
                        (field-desc-width f)))
          ;; Decode this field's value for potential use by later field-refs
          (define val
            (cond
              [(eq? (field-desc-type f) 'padding) #f]
              [(eq? (field-desc-type f) 'uint)
               (decode-uint-simple data byte-off w (field-desc-byte-order f))]
              [(eq? (field-desc-type f) 'sint)
               (decode-sint-simple data byte-off w (field-desc-byte-order f))]
              [else #f]))
          (vector-set! boundaries i (list 'byte byte-off w))
          (loop (cdr fs) (+ byte-off w) 0 (+ i 1)
                (if val (hash-set decoded (field-desc-name f) val) decoded))])])))

;; Simple uint decode for boundary computation
(define (decode-uint-simple data offset width order)
  (case order
    [(big)
     (for/fold ([acc 0]) ([i (in-range width)])
       (bitwise-ior (arithmetic-shift acc 8)
                    (bytes-ref data (+ offset i))))]
    [(little)
     (for/fold ([acc 0]) ([i (in-range (sub1 width) -1 -1)])
       (bitwise-ior (arithmetic-shift acc 8)
                    (bytes-ref data (+ offset i))))]))

(define (decode-sint-simple data offset width order)
  (define unsigned (decode-uint-simple data offset width order))
  (define sign-bit (expt 2 (sub1 (* 8 width))))
  (if (>= unsigned sign-bit)
      (- unsigned (expt 256 width))
      unsigned))

;; ============================================================
;; Match expander helper (compile-time)
;; ============================================================

;; Translate a width syntax form to a runtime expression.
;; Recognizes: nat, (field-ref name), (compute source-expr)
(define-for-syntax (width-stx->expr w-stx)
  (cond
    [(nat-stx? w-stx) w-stx]
    [(and (syntax->list w-stx)
          (= (length (syntax->list w-stx)) 2)
          (eq? (syntax-e (car (syntax->list w-stx))) 'field-ref))
     (define ref-name (cadr (syntax->list w-stx)))
     #`(make-field-ref '#,ref-name)]
    [(and (syntax->list w-stx)
          (>= (length (syntax->list w-stx)) 2)
          (eq? (syntax-e (car (syntax->list w-stx))) 'compute))
     (define body (cadr (syntax->list w-stx)))
     ;; The body is an expression using (field-ref name) forms.
     ;; We need to build a lambda that takes a lookup function.
     ;; Replace (field-ref name) with (lk 'name) in the body.
     (define (transform-compute-body body-stx)
       (cond
         [(and (syntax->list body-stx)
               (= (length (syntax->list body-stx)) 2)
               (eq? (syntax-e (car (syntax->list body-stx))) 'field-ref))
          (define ref-name (cadr (syntax->list body-stx)))
          #`(lk '#,ref-name)]
         [(syntax->list body-stx)
          (datum->syntax body-stx
                         (map transform-compute-body (syntax->list body-stx))
                         body-stx)]
         [else body-stx]))
     (define transformed (transform-compute-body body))
     #`(make-compute '#,body (λ (lk) #,transformed))]
    [else
     (raise-syntax-error 'struct/wire
                         "invalid width expression: expected nat, (field-ref name), or (compute expr)"
                         w-stx)]))

(define-for-syntax (nat-stx? stx)
  (let ([v (syntax-e stx)])
    (and (integer? v) (exact? v) (>= v 0))))

(define-for-syntax (wire-struct-match-transform pred-id accessor-table pat-stx)
  (syntax-parse pat-stx
    [(_)
     #`(? #,pred-id)]
    [(_ (~seq kw:keyword pat) ...)
     #`(? #,pred-id
          #,@(for/list ([k (in-list (syntax->list #'(kw ...)))]
                        [p (in-list (syntax->list #'(pat ...)))])
               (define kw-str (keyword->string (syntax-e k)))
               (define acc (hash-ref accessor-table kw-str
                             (λ () (raise-syntax-error
                                    'match
                                    (format "unknown field keyword ~a" (syntax-e k))
                                    k))))
               #`(app #,acc #,p)))]))

;; ============================================================
;; struct/wire macro
;; ============================================================

(define-syntax (struct/wire stx)
  (syntax-parse stx
    [(_ sname:id
        (~optional (~seq #:byte-order default-bo:id)
                   #:defaults ([default-bo #'big]))
        (~optional (~seq #:bit-order default-bito:id)
                   #:defaults ([default-bito #f]))
        field-clause ...)

     ;; Parse field clauses: 9-element list
     ;; (name type width-stx byte-order-or-#f unit-or-#f
     ;;  bit-order-or-#f compute-or-#f contract-or-#f align-or-#f)
     (define raw-field-infos
       (for/list ([fc (in-list (syntax->list #'(field-clause ...)))])
         (syntax-parse fc
           ;; Padding with #:align — no explicit width
           [(fname:id ftype:id #:align falign:nat)
            #:when (eq? (syntax-e #'ftype) 'padding)
            (list #'fname #'ftype #f
                  #f #f #f #f #f (syntax-e #'falign) #f)]
           ;; Normal field clause
           [(fname:id ftype:id fwidth
                      (~optional (~seq #:byte-order fbo:id))
                      (~optional (~seq #:unit funit:id))
                      (~optional (~seq #:bit-order fbito:id))
                      (~optional (~seq #:compute fcompute:expr))
                      (~optional (~seq #:contract fcontract:expr))
                      (~optional (~seq #:present-when fpresent:expr)))
            (list #'fname #'ftype #'fwidth
                  (attribute fbo) (attribute funit) (attribute fbito)
                  (attribute fcompute) (attribute fcontract) #f
                  (attribute fpresent))])))

     ;; Resolve #:align padding widths based on static offsets.
     ;; Walks fields, tracks byte offset, computes padding for #:align fields.
     (define field-infos
       (let loop ([infos raw-field-infos] [byte-off 0] [bit-acc 0] [acc '()])
         (cond
           [(null? infos)
            (reverse acc)]
           ;; Auto-align padding: compute width from current offset
           [(ninth (car infos))
            (define info (car infos))
            (define align-val (ninth info))
            ;; Flush any accumulated bits first
            (define flush-bytes (if (> bit-acc 0) (quotient bit-acc 8) 0))
            (define cur-off (+ byte-off flush-bytes))
            (define pad-width (modulo (- align-val (modulo cur-off align-val)) align-val))
            (if (zero? pad-width)
                ;; Already aligned — skip this padding field
                (loop (cdr infos) cur-off 0 acc)
                ;; Insert padding with computed width
                (let ([new-info (list (first info)
                                     (second info)
                                     (datum->syntax (first info) pad-width)
                                     #f #f #f #f #f #f #f)])
                  (loop (cdr infos) (+ cur-off pad-width) 0 (cons new-info acc))))]
           ;; Bitfield: accumulate bits
           [(and (fifth (car infos))
                 (eq? (syntax-e (fifth (car infos))) 'bits))
            (define info (car infos))
            (define w (syntax-e (third info)))
            (define new-bits (+ bit-acc w))
            (if (zero? (modulo new-bits 8))
                (loop (cdr infos) (+ byte-off (quotient new-bits 8)) 0 (cons info acc))
                (loop (cdr infos) byte-off new-bits (cons info acc)))]
           ;; Normal byte field
           [else
            (define info (car infos))
            (define flush-bytes (if (> bit-acc 0) (quotient bit-acc 8) 0))
            (define w (if (third info) (if (nat-stx? (third info)) (syntax-e (third info)) 0) 0))
            (loop (cdr infos) (+ byte-off flush-bytes w) 0 (cons info acc))])))

     (define field-names  (map first field-infos))
     (define field-widths (map third field-infos))

     ;; Determine if a field has a variable-length width (not a literal nat)
     (define (variable-width? info)
       (define w (third info))
       (not (let ([v (syntax-e w)]) (and (integer? v) (exact? v) (>= v 0)))))

     (define (field-conditional? info)
       (and (tenth info) #t))

     (define has-variable-fields?
       (ormap (λ (info) (or (variable-width? info) (field-conditional? info)))
              field-infos))

     (define (bitfield? info)
       (define u (fifth info))
       (and u (eq? (syntax-e u) 'bits)))

     ;; Field index for each field
     (define field-indices (range (length field-infos)))

     ;; Resolve effective bit-order for a compile-time field-info
     (define (info-effective-bit-order info)
       (define fbi (sixth info))
       (define proto-bito (attribute default-bito))
       (cond
         [fbi (syntax-e fbi)]
         [proto-bito (syntax-e proto-bito)]
         [else 'msb]))

     ;; Collect a compile-time bitfield group (split on bit-order change)
     (define (collect-static-bitfield-group infos)
       (define (effective-bo info) (info-effective-bit-order info))
       (let loop ([is infos] [group '()] [bits 0] [group-bo #f])
         (cond
           [(and (pair? is)
                 (bitfield? (car is))
                 (or (not group-bo)
                     (eq? group-bo (effective-bo (car is)))))
            (define i (car is))
            (loop (cdr is) (cons i group)
                  (+ bits (syntax-e (third i)))
                  (or group-bo (effective-bo i)))]
           [else
            (values (reverse group) bits (or group-bo 'msb) is)])))

     ;; Compute static accessor infos (only used when no variable fields)
     (define static-accessor-infos
       (if has-variable-fields?
           #f  ;; will use boundaries at runtime
           (let loop ([infos field-infos] [byte-off 0] [acc '()])
             (cond
               [(null? infos) acc]
               [(bitfield? (car infos))
                (define-values (group group-bits group-bo remaining)
                  (collect-static-bitfield-group infos))
                (define group-bytes (quotient group-bits 8))
                (define group-acc
                  (let gloop ([gs group] [bit-pos 0] [gacc '()])
                    (if (null? gs)
                        (reverse gacc)
                        (let ([w (syntax-e (third (car gs)))])
                          (gloop (cdr gs) (+ bit-pos w)
                                 (cons (list 'bits byte-off group-bytes bit-pos w group-bo) gacc))))))
                (loop remaining (+ byte-off group-bytes) (append acc group-acc))]
               [else
                (define w (syntax-e (third (car infos))))
                (loop (cdr infos) (+ byte-off w)
                      (append acc (list (list 'byte byte-off))))]))))

     ;; Keywords from field names
     (define field-kws
       (map (λ (fn) (string->keyword (symbol->string (syntax-e fn))))
            field-names))

     ;; Sorted indices for keyword arg ordering
     (define sorted-idxs
       (sort (range (length field-kws))
             keyword<? #:key (λ (i) (list-ref field-kws i))))

     ;; Identifiers
     (define instance-id (generate-temporary (format-id #'sname "~a-inst" #'sname)))
     (define inst-pred   (format-id instance-id "~a?" instance-id))
     (define inst-bytes  (format-id instance-id "~a-bytes" instance-id))
     (define inst-offset (format-id instance-id "~a-offset" instance-id))
     (define inst-bounds (format-id instance-id "~a-boundaries" instance-id))
     (define desc-id     (generate-temporary #'sname))
     (define pred-id     (format-id #'sname "~a?" #'sname))
     (define encode-id   (format-id #'sname "~a-encode" #'sname))
     (define decode-id   (format-id #'sname "~a-decode" #'sname))

     (define accessor-ids
       (map (λ (fn) (format-id #'sname "~a-~a" #'sname fn))
            field-names))

     ;; Build width expression for field-desc construction
     (define (width-expr info)
       (define w-stx (third info))
       (if (nat-stx? w-stx)
           w-stx
           ;; It's a form like (field-ref name) or (compute ...)
           w-stx))

     ;; Field descriptor expressions
     (define (field-computed? info)
       (and (seventh info) #t))

     (define (field-padding? info)
       (eq? (syntax-e (second info)) 'padding))

     (define fd-exprs
       (for/list ([info field-infos])
         (define fn (first info))
         (define ft (second info))
         (define fw-stx (third info))
         (define fb (fourth info))
         (define fu (fifth info))
         (define fbi (sixth info))    ;; bit-order
         (define fc (seventh info))   ;; compute
         (define fk (eighth info))    ;; contract
         ;; ninth = align (already resolved)
         (define fp (tenth info))     ;; present-when
         (define bo-expr (if fb #`'#,fb #`'default-bo))
         (define width-arg (width-stx->expr fw-stx))
         ;; Resolve effective bit-order for this field
         (define effective-bito
           (or fbi (and (attribute default-bito) #'default-bito)))
         ;; Build optional keyword args
         (define kw-args
           (append (if fu (list #'#:unit #`'#,fu) '())
                   (if effective-bito (list #'#:bit-order #`'#,effective-bito) '())
                   (if fc (list #'#:compute fc) '())
                   (if fk (list #'#:contract fk) '())
                   (if fp (list #'#:present-when fp) '())))
         #`(make-field-desc '#,fn '#,ft #,width-arg #,bo-expr #,@kw-args)))

     ;; Encode function formals: exclude computed and padding fields from keyword args
     (define encode-sorted-idxs
       (filter (λ (i) (define info (list-ref field-infos i))
                       (not (or (field-computed? info) (field-padding? info))))
               sorted-idxs))

     (define encode-sorted-params
       (for/list ([i encode-sorted-idxs])
         (generate-temporary (list-ref field-names i))))

     (define encode-formals
       (apply append
              (for/list ([i encode-sorted-idxs]
                         [param encode-sorted-params])
                (list (datum->syntax #'sname (list-ref field-kws i))
                      param))))

     (define encode-hash-pairs
       (apply append
              (for/list ([i encode-sorted-idxs]
                         [param encode-sorted-params])
                (define fn (list-ref field-names i))
                (list #`'#,fn param))))

     ;; Accessor definitions (skip padding fields)
     (define accessor-defs
       (if has-variable-fields?
           ;; Dynamic accessors using precomputed boundaries
           (for/list ([aid accessor-ids]
                      [fn field-names]
                      [info field-infos]
                      [idx field-indices]
                      #:unless (field-padding? info))
             (define ft (second info))
             #`(define (#,aid v)
                 (define bounds (vector-ref (#,inst-bounds v) #,idx))
                 (case (car bounds)
                   [(absent) #f]
                   [(byte)
                    (decode-field (#,inst-bytes v) (second bounds)
                                 (make-field-desc '#,fn '#,ft (third bounds)
                                                  (field-desc-byte-order
                                                   (list-ref (protocol-desc-fields #,desc-id) #,idx))))]
                   [(bits)
                    (decode-bitfield (#,inst-bytes v)
                                    (second bounds) (third bounds)
                                    (fourth bounds) (fifth bounds)
                                    '#,ft
                                    #:bit-order (sixth bounds))])))
           ;; Static accessors (compile-time offsets)
           (for/list ([aid accessor-ids]
                      [fn field-names]
                      [info field-infos]
                      [ai static-accessor-infos]
                      #:unless (field-padding? info))
             (define ft (second info))
             (case (car ai)
               [(byte)
                (define byte-off (second ai))
                #`(define (#,aid v)
                    (decode-field (#,inst-bytes v)
                                  (+ (#,inst-offset v) #,byte-off)
                                  (protocol-desc-field-ref #,desc-id '#,fn)))]
               [(bits)
                (define group-byte-off (second ai))
                (define group-bytes (third ai))
                (define bit-offset (fourth ai))
                (define bit-width (fifth ai))
                (define bit-ord (sixth ai))
                #`(define (#,aid v)
                    (decode-bitfield (#,inst-bytes v)
                                     (+ (#,inst-offset v) #,group-byte-off)
                                     #,group-bytes
                                     #,bit-offset
                                     #,bit-width
                                     '#,ft
                                     #:bit-order '#,(datum->syntax #'sname bit-ord)))]))))

     ;; Accessor table for match expander (skip padding)
     (define accessor-table-for-match
       (for/list ([fn field-names]
                  [aid accessor-ids]
                  [info field-infos]
                  #:unless (field-padding? info))
         (cons (symbol->string (syntax-e fn)) aid)))

     #`(begin
         ;; Instance struct
         #,(if has-variable-fields?
               #`(struct #,instance-id (bytes offset boundaries))
               #`(struct #,instance-id (bytes offset)))

         ;; Protocol descriptor
         (define #,desc-id
           (make-protocol-desc 'sname (list #,@fd-exprs)))

         ;; Predicate
         (define (#,pred-id v) (#,inst-pred v))

         ;; Field accessors
         #,@accessor-defs

         ;; Encode: keyword args → bytes
         (define (#,encode-id #,@encode-formals)
           (encode #,desc-id (hasheq #,@encode-hash-pairs)))

         ;; Decode: bytes [#:offset n] → instance
         #,(if has-variable-fields?
               #`(define (#,decode-id data #:offset [offset 0])
                   (define bounds (compute-field-boundaries #,desc-id data offset))
                   (#,instance-id data offset bounds))
               #`(define (#,decode-id data #:offset [offset 0])
                   (#,instance-id data offset)))

         ;; Match expander + expression transformer
         (define-match-expander sname
           (λ (pat-stx)
             (wire-struct-match-transform
              #'#,pred-id
              (hash #,@(apply
                        append
                        (for/list ([entry accessor-table-for-match])
                          (list (car entry) #`#'#,(cdr entry)))))
              pat-stx))
           (λ (expr-stx) #'#,desc-id)))]))
