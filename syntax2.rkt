#lang racket/base

;; ============================================================
;; struct/wire macro (redesigned)
;;
;; Parses syntax into IR. Generates bindings that delegate to
;; ir-encode / ir-decode. One accessor path. No positional lists.
;; ============================================================

(require (for-syntax racket/base
                     racket/list
                     racket/syntax
                     syntax/parse)
         racket/match
         wirey/ir
         wirey/ir-codec)

(provide struct/wire)

;; ============================================================
;; Compile-time: field metadata (what the macro tracks per field)
;; ============================================================

;; A field-meta records what the macro needs for code generation:
;;   name-stx  : syntax identifier
;;   optional?  : boolean (case-branch fields are optional)
;;   default    : syntax or #f
;;   padding?   : boolean
;;   computed?  : boolean
;;   enum?      : syntax or #f (the enum expression)
(begin-for-syntax
  (struct field-meta (name-stx optional? default padding? computed? enum? bit-width) #:transparent)

  ;; Collect all field-metas from an element tree (for keyword/accessor generation)
  (define (collect-metas elem-infos)
    (apply append
           (for/list ([info elem-infos])
             (case (car info)
               [(field) (list (second info))]
               [(bit-field) (list (second info))]
               [(bitfield-group)
                (for/list ([bf (second info)])
                  (cdr bf))]  ;; bf is (cons 'bit-field meta)
               [(case-block)
                (define branches (second info))
                (define branch-metas
                  (apply append
                         (for/list ([br branches])
                           (collect-metas (cdr br)))))
                (for/list ([m branch-metas])
                  (struct-copy field-meta m [optional? #t]))]
               [(padding-info) '()]
               [else '()]))))

  ;; Deduplicate metas by name (keep first occurrence)
  (define (dedup-metas metas)
    (let loop ([ms metas] [seen '()] [acc '()])
      (cond
        [(null? ms) (reverse acc)]
        [(memq (syntax-e (field-meta-name-stx (car ms))) seen)
         (loop (cdr ms) seen acc)]
        [else
         (loop (cdr ms)
               (cons (syntax-e (field-meta-name-stx (car ms))) seen)
               (cons (car ms) acc))]))))

;; ============================================================
;; Compile-time: parse field clauses into IR expressions + metas
;; ============================================================

(begin-for-syntax
  ;; Parse a single normal field clause.
  ;; Returns (cons 'field field-meta) + the IR expression syntax.
  ;; Actually returns: (list kind meta ir-expr)
  (define (parse-field-clause fc default-bo default-bito)
    (syntax-parse fc
      ;; Padding with #:align
      [(fname:id (~datum padding) #:align falign:nat)
       (list 'padding-info
             (field-meta #'fname #f #f #t #f #f #f)
             ;; Alignment padding — will need resolution, for now just fixed
             #`(wire-padding (width-fixed #,(syntax-e #'falign))))]

      ;; Explicit padding
      [(fname:id (~datum padding) fwidth:nat)
       (list 'padding-info
             (field-meta #'fname #f #f #t #f #f #f)
             #`(wire-padding (width-fixed fwidth)))]

      ;; Normal field
      [(fname:id ftype:id fwidth
                 (~optional (~seq #:byte-order fbo:id))
                 (~optional (~seq #:unit funit:id))
                 (~optional (~seq #:bit-order fbito:id))
                 (~optional (~seq #:compute fcompute:expr))
                 (~optional (~seq #:contract fcontract:expr))
                 (~optional (~seq #:present-when fpresent:expr))
                 (~optional (~seq #:default fdefault:expr))
                 (~optional (~seq #:terminator fterm:nat))
                 (~optional (~seq #:enum fenum:expr))
                 (~optional (~seq #:repeat frepeat))
                 (~optional (~seq #:repeat-until frepuntil:expr)))
       (define bo (or (attribute fbo) default-bo))
       (define unit-sym (and (attribute funit) (syntax-e #'funit)))
       (define is-bits? (eq? unit-sym 'bits))
       (define is-computed? (and (attribute fcompute) #t))
       (define is-padding? (eq? (syntax-e #'ftype) 'padding))

       (define meta (field-meta #'fname #f
                                (attribute fdefault)
                                is-padding?
                                is-computed?
                                (attribute fenum)
                                (if is-bits? (syntax-e #'fwidth) #f)))

       ;; Build width expression
       (define width-expr (parse-width #'fwidth))

       ;; Build options hash expression
       (define opts-pairs
         (filter values
           (list (and (attribute fcompute) #`(cons 'compute #,(attribute fcompute)))
                 (and (attribute fcontract) #`(cons 'contract #,(attribute fcontract)))
                 (and (attribute fpresent) #`(cons 'present-when #,(attribute fpresent)))
                 (and (attribute fterm) #`(cons 'terminator fterm))
                 (and (attribute fenum) #`(cons 'enum #,(attribute fenum)))
                 (and (attribute frepeat) #`(cons 'repeat #,(parse-width (attribute frepeat))))
                 (and (attribute frepuntil) #`(cons 'repeat-until #,(attribute frepuntil))))))
       (define opts-expr #`(hasheq #,@(apply append
                                        (for/list ([p opts-pairs])
                                          (list #`(car #,p) #`(cdr #,p))))))
       ;; Actually, building hasheq from cons pairs is awkward. Use make-immutable-hash.
       (define opts-expr2 #`(make-immutable-hash (list #,@opts-pairs)))

       (if is-bits?
           ;; Bit field — will be grouped later
           (list 'bit-field meta
                 #`(wire-bit-field 'fname 'ftype fwidth #,opts-expr2))
           ;; Byte field
           (list 'field meta
                 #`(wire-field 'fname 'ftype #,width-expr '#,bo #,opts-expr2)))]))

  ;; Parse a width expression (nat, (field-ref name), (compute body), or general expr)
  (define (parse-width w-stx)
    (cond
      [(and (syntax? w-stx)
            (let ([v (syntax-e w-stx)])
              (and (integer? v) (exact? v) (> v 0))))
       #`(width-fixed #,(syntax-e w-stx))]
      [(and (syntax->list w-stx)
            (= (length (syntax->list w-stx)) 2)
            (eq? (syntax-e (car (syntax->list w-stx))) 'field-ref))
       (define name (cadr (syntax->list w-stx)))
       #`(width-field-ref '#,name)]
      [(and (syntax->list w-stx)
            (>= (length (syntax->list w-stx)) 2)
            (eq? (syntax-e (car (syntax->list w-stx))) 'compute))
       (define body (cadr (syntax->list w-stx)))
       (define body-list (syntax->list body))
       (if (and body-list
                (>= (length body-list) 2)
                (memq (syntax-e (car body-list)) '(λ lambda)))
           #`(width-compute #,body)
           ;; Transform (field-ref name) → (lk 'name) in body
           (let ()
             (define (transform b)
               (cond
                 [(and (syntax->list b)
                       (= (length (syntax->list b)) 2)
                       (eq? (syntax-e (car (syntax->list b))) 'field-ref))
                  #`(lk '#,(cadr (syntax->list b)))]
                 [(syntax->list b)
                  (datum->syntax b (map transform (syntax->list b)) b)]
                 [else b]))
             #`(width-compute (λ (lk) #,(transform body)))))]
      [else
       ;; Pass through as runtime expression
       w-stx]))

  ;; Parse a full field clause list (top-level), handling #:case
  ;; Returns: (list elem-info ...) where each elem-info is
  ;;   (list 'field meta ir-expr)
  ;;   (list 'bit-field meta ir-expr)
  ;;   (list 'case-block (list branch ...) ir-expr)
  ;;   (list 'padding-info meta ir-expr)
  (define (parse-clauses clauses default-bo default-bito)
    (let loop ([cs clauses] [acc '()])
      (if (null? cs)
          (reverse acc)
          (let ([fc (car cs)])
            (syntax-parse fc
              ;; Case block
              [(#:case disc:id branch ...)
               (define branches
                 (for/list ([br (syntax->list #'(branch ...))])
                   (syntax-parse br
                     [((pred-or-val) inner ...)
                      (define inner-infos
                        (parse-clauses (syntax->list #'(inner ...))
                                       default-bo default-bito))
                      (cons #'pred-or-val inner-infos)])))
               ;; Build IR expression
               (define ir-expr
                 #`(wire-case 'disc
                     (list #,@(for/list ([br branches])
                                (define pred-stx (car br))
                                (define inner-infos (cdr br))
                                (define inner-ir-exprs
                                  (map third (filter (λ (i) (third i)) inner-infos)))
                                #`(wire-case-branch
                                   #,pred-stx
                                   (list #,@inner-ir-exprs))))))
               (loop (cdr cs)
                     (cons (list 'case-block branches ir-expr) acc))]

              ;; Normal field clause
              [_
               (define info (parse-field-clause fc default-bo default-bito))
               (loop (cdr cs) (cons info acc))])))))

  ;; Group consecutive bit-fields into wire-bitfield-group elements.
  ;; Returns a list of elem-infos where bit-fields are grouped.
  (define (group-bitfields elem-infos default-bito)
    (let loop ([infos elem-infos] [acc '()])
      (cond
        [(null? infos) (reverse acc)]
        [(eq? (car (car infos)) 'bit-field)
         ;; Collect consecutive bit-fields
         (define-values (group remaining)
           (let grp ([is infos] [g '()] [bits 0])
             (if (and (pair? is) (eq? (car (car is)) 'bit-field))
                 (grp (cdr is) (cons (car is) g)
                      (+ bits (field-meta-bit-width (second (car is)))))
                 (values (reverse g) is))))
         (define total-bits
           (for/sum ([bf group])
             (field-meta-bit-width (second bf))))
         (define bit-order (or default-bito 'msb))
         ;; Build grouped IR
         (define group-ir
           #`(wire-bitfield-group
               (list #,@(map third group))
               '#,bit-order
               #,total-bits))
         (define group-meta
           (list 'bitfield-group
                 (map (λ (i) (cons 'bit-field (second i))) group)
                 group-ir))
         (loop remaining (cons group-meta acc))]
        [else
         (loop (cdr infos) (cons (car infos) acc))]))))

;; ============================================================
;; Compile-time: match expander helper
;; ============================================================

(define-for-syntax (wire-match-transform pred-id accessor-table pat-stx)
  (syntax-parse pat-stx
    [(_)
     #`(? #,pred-id)]
    [(_ (~seq kw:keyword pat) ...)
     #`(? #,pred-id
          #,@(for/list ([k (syntax->list #'(kw ...))]
                        [p (syntax->list #'(pat ...))])
               (define kw-str (keyword->string (syntax-e k)))
               (define acc (hash-ref accessor-table kw-str
                             (λ () (raise-syntax-error
                                    'match (format "unknown field: ~a" kw-str) k))))
               #`(app #,acc #,p)))]))

;; ============================================================
;; The macro
;; ============================================================

(define-syntax (struct/wire stx)
  (syntax-parse stx
    [(_ sname:id
        (~optional (~seq #:byte-order default-bo:id)
                   #:defaults ([default-bo #'big]))
        (~optional (~seq #:bit-order default-bito:id)
                   #:defaults ([default-bito #f]))
        (~optional (~seq #:alignment default-align:nat)
                   #:defaults ([default-align #f]))
        (~optional (~seq #:encode encode-fn:expr))
        (~optional (~seq #:decode decode-fn:expr))
        field-clause ...)

     ;; --- Parse ---
     (define default-bo-sym (syntax-e #'default-bo))
     (define default-bito-sym (and (attribute default-bito)
                                   (syntax-e #'default-bito)))

     (define raw-infos
       (parse-clauses (syntax->list #'(field-clause ...))
                      #'default-bo
                      (attribute default-bito)))

     ;; Group bitfields
     (define grouped-infos (group-bitfields raw-infos default-bito-sym))

     ;; Collect all field metas (for keywords/accessors)
     (define all-metas (dedup-metas (collect-metas grouped-infos)))

     ;; Extract IR element expressions
     (define ir-elements (filter-map third grouped-infos))

     ;; --- Generate identifiers ---
     (define inst-id    (generate-temporary (format-id #'sname "~a-inst" #'sname)))
     (define inst-pred  (format-id inst-id "~a?" inst-id))
     (define inst-bytes (format-id inst-id "~a-bytes" inst-id))
     (define inst-off   (format-id inst-id "~a-offset" inst-id))
     (define proto-id   (generate-temporary #'sname))
     (define pred-id    (format-id #'sname "~a?" #'sname))
     (define encode-id  (format-id #'sname "~a-encode" #'sname))
     (define decode-id  (format-id #'sname "~a-decode" #'sname))

     ;; Field names for accessors (exclude padding and computed)
     (define accessor-metas
       (filter (λ (m) (not (field-meta-padding? m))) all-metas))
     (define accessor-ids
       (for/list ([m accessor-metas])
         (format-id #'sname "~a-~a" #'sname (field-meta-name-stx m))))

     ;; --- Encode keyword formals ---
     ;; Exclude padding and computed. Case-branch fields are optional (#f default).
     (define encode-metas
       (filter (λ (m) (and (not (field-meta-padding? m))
                           (not (field-meta-computed? m))))
               all-metas))
     (define encode-kws
       (for/list ([m encode-metas])
         (string->keyword (symbol->string (syntax-e (field-meta-name-stx m))))))
     (define sorted-encode-idxs
       (sort (range (length encode-kws))
             keyword<? #:key (λ (i) (list-ref encode-kws i))))

     (define encode-params
       (for/list ([i sorted-encode-idxs])
         (generate-temporary (field-meta-name-stx (list-ref encode-metas i)))))

     (define encode-formals
       (apply append
              (for/list ([i sorted-encode-idxs]
                         [param encode-params])
                (define m (list-ref encode-metas i))
                (define kw (datum->syntax #'sname (list-ref encode-kws i)))
                (cond
                  [(field-meta-optional? m) (list kw (list param #'#f))]
                  [(field-meta-default m)   (list kw (list param (field-meta-default m)))]
                  [else                     (list kw param)]))))

     (define encode-hash-pairs
       (apply append
              (for/list ([i sorted-encode-idxs]
                         [param encode-params])
                (define m (list-ref encode-metas i))
                (define fn (field-meta-name-stx m))
                (list #`'#,fn param))))

     ;; --- Match accessor table ---
     (define accessor-table-entries
       (for/list ([m accessor-metas] [aid accessor-ids])
         (cons (symbol->string (syntax-e (field-meta-name-stx m))) aid)))

     ;; --- Output ---
     #`(begin
         ;; Instance struct
         (struct #,inst-id (bytes offset))

         ;; Protocol IR
         (define #,proto-id
           (wire-protocol 'sname
             (list #,@ir-elements)
             (hasheq #,@(if (attribute default-align)
                            (list #''alignment #'default-align)
                            '()))))

         ;; Predicate
         (define (#,pred-id v) (#,inst-pred v))

         ;; Encode: keyword args → bytes
         (define (#,encode-id #,@encode-formals)
           (ir-encode #,proto-id (hasheq #,@encode-hash-pairs)))

         ;; Decode: bytes → instance
         (define (#,decode-id data #:offset [offset 0])
           (#,inst-id data offset))

         ;; Accessors: ONE path — decode + hash-ref
         #,@(for/list ([m accessor-metas] [aid accessor-ids])
              (define fn (field-meta-name-stx m))
              #`(define (#,aid v)
                  (hash-ref (ir-decode #,proto-id (#,inst-bytes v)
                                       #:offset (#,inst-off v))
                            '#,fn #f)))

         ;; Match expander + expression transformer
         (define-match-expander sname
           (λ (pat-stx)
             (wire-match-transform
              #'#,pred-id
              (hash #,@(apply append
                        (for/list ([entry accessor-table-entries])
                          (list (car entry) #`#'#,(cdr entry)))))
              pat-stx))
           (λ (expr-stx) #'#,proto-id))

         ;; Optional value-level encode/decode
         #,@(if (attribute encode-fn)
                (let ([ev-id (format-id #'sname "~a-encode-value" #'sname)])
                  (list #`(define (#,ev-id v)
                            (ir-encode #,proto-id (#,(attribute encode-fn) v)))))
                '())
         #,@(if (attribute decode-fn)
                (let ([dv-id (format-id #'sname "~a-decode-value" #'sname)])
                  (list #`(define (#,dv-id data #:offset [offset 0])
                            (#,(attribute decode-fn)
                             (ir-decode #,proto-id data #:offset offset)))))
                '()))]))
