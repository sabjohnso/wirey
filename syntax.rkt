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
         wirey/length-expr
         wirey/enum
         wirey/case-block)

(provide struct/wire
         compute-decoded-offset
         protocol-desc-total-size-at)

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
;; Runtime helpers for repeated-struct decoding
;; ============================================================

;; Compute the byte offset after all fixed/decoded fields in a protocol-desc.
;; Stops before any field that isn't in the decoded hash.
(define (compute-decoded-offset pd decoded base-offset)
  (define fields (protocol-desc-fields pd))
  (let loop ([fs fields] [off base-offset])
    (cond
      [(null? fs) off]
      [(case-block? (car fs))
       ;; Find the active branch and add its size
       (define cb (car fs))
       (define disc-val (hash-ref decoded (case-block-discriminator cb) #f))
       (define br (and disc-val (case-block-select-branch cb disc-val)))
       (define branch-off
         (if br
             (for/fold ([o off]) ([bf (in-list (case-branch-fields br))])
               (define raw-w (field-desc-width bf))
               (define w
                 (cond
                   [(exact-positive-integer? raw-w) raw-w]
                   [else
                    (define val (hash-ref decoded (field-desc-name bf) #f))
                    (cond
                      [(bytes? val) (bytes-length val)]
                      [(string? val) (string-length val)]
                      [else 0])]))
               (+ o w))
             off))
       (loop (cdr fs) branch-off)]
      [(not (field-desc? (car fs))) (loop (cdr fs) off)]
      [(not (hash-has-key? decoded (field-desc-name (car fs)))) off]
      [(eq? (field-desc-type (car fs)) 'padding)
       (loop (cdr fs) (+ off (field-desc-width (car fs))))]
      [(field-desc-conditional? (car fs))
       (if (hash-ref decoded (field-desc-name (car fs)) #f)
           (loop (cdr fs) (+ off (field-desc-width (car fs))))
           (loop (cdr fs) off))]
      [(eq? (field-desc-unit (car fs)) 'bits)
       ;; Skip bitfields — they were already counted in the group
       (define-values (group group-bits remaining)
         (collect-bitfield-group fs))
       (loop remaining (+ off (quotient group-bits 8)))]
      [else
       (define w (field-desc-width (car fs)))
       (if (exact-positive-integer? w)
           (loop (cdr fs) (+ off w))
           ;; Variable-width: compute from decoded value
           (let ([val (hash-ref decoded (field-desc-name (car fs)) #f)])
             (define actual-w
               (cond
                 [(bytes? val) (bytes-length val)]
                 [(string? val) (string-length val)]
                 [else 0]))
             (loop (cdr fs) (+ off actual-w))))])))

;; Compute the size of a struct decoded at a given offset.
;; Uses decode to get the hash, then computes total consumed bytes.
(define (protocol-desc-total-size-at data offset pd)
  (define decoded (decode pd data #:offset offset))
  (- (compute-decoded-offset pd decoded offset) offset))

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
     ;; Check if body is already a lambda: (λ (arg) ...)
     (define body-list (syntax->list body))
     (if (and body-list
              (>= (length body-list) 2)
              (memq (syntax-e (car body-list)) '(λ lambda)))
         ;; Body is a lambda — use it directly as the compute function
         #`(make-compute '#,body #,body)
         ;; Body uses (field-ref name) forms — transform to lambda
         (let ()
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
           #`(make-compute '#,body (λ (lk) #,transformed))))]
    [else
     ;; Pass through as a runtime expression (e.g., protocol-desc-total-size call)
     w-stx]))

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
        (~optional (~seq #:alignment default-align:nat)
                   #:defaults ([default-align #f]))
        field-clause ...)

     ;; Parse field clauses: 9-element list
     ;; (name type width-stx byte-order-or-#f unit-or-#f
     ;;  bit-order-or-#f compute-or-#f contract-or-#f align-or-#f)
     ;; Parse a single normal field clause into a 12-element info list.
     (define (parse-normal-field fc)
       (syntax-parse fc
         ;; Padding with #:align — no explicit width
         [(fname:id ftype:id #:align falign:nat)
          #:when (eq? (syntax-e #'ftype) 'padding)
          (list #'fname #'ftype #f
                #f #f #f #f #f (syntax-e #'falign) #f #f #f)]
         ;; Embedded struct field (single)
         [(fname:id fstruct:id #:struct)
          (list #'fname (list 'embedded #'fstruct) #f
                #f #f #f #f #f #f #f #f #f)]
         ;; Repeated struct field
         [(fname:id fstruct:id #:repeat frepeat #:struct)
          (list #'fname (list 'repeated-struct #'fstruct) #f
                #f #f #f #f #f #f #f #f
                (list 'repeated-struct #'fstruct #'frepeat))]
         ;; Normal field clause
         [(fname:id ftype:id fwidth
                    (~optional (~seq #:byte-order fbo:id))
                    (~optional (~seq #:unit funit:id))
                    (~optional (~seq #:bit-order fbito:id))
                    (~optional (~seq #:compute fcompute:expr))
                    (~optional (~seq #:contract fcontract:expr))
                    (~optional (~seq #:present-when fpresent:expr))
                    (~optional (~seq #:default fdefault:expr))
                    (~optional (~seq #:enum fenum:expr)))
          (list #'fname #'ftype #'fwidth
                (attribute fbo) (attribute funit) (attribute fbito)
                (attribute fcompute) (attribute fcontract) #f
                (attribute fpresent) (attribute fdefault)
                (attribute fenum))]))

     ;; Parse field clauses, recognizing #:case blocks.
     ;; Returns a list of items — each is either:
     ;;   - A 12-element field-info list (for normal fields)
     ;;   - A (list 'case-block disc-name-stx branches) where each branch is
     ;;     (list pred-or-val-stx (listof field-info))
     (define raw-field-infos
       (let loop ([clauses (syntax->list #'(field-clause ...))] [acc '()])
         (cond
           [(null? clauses) (reverse acc)]
           [else
            (define fc (car clauses))
            (syntax-parse fc
              ;; Case block: (#:case disc-field [pred fields...] ...)
              [(#:case disc:id branch ...)
               (define branches
                 (for/list ([br (in-list (syntax->list #'(branch ...)))])
                   (syntax-parse br
                     [((pred-or-val) inner-field ...)
                      (define inner-infos
                        (for/list ([inf (in-list (syntax->list #'(inner-field ...)))])
                          (parse-normal-field inf)))
                      (list #'pred-or-val inner-infos)])))
               (loop (cdr clauses)
                     (cons (list 'case-block #'disc branches) acc))]
              ;; Normal field
              [_
               (loop (cdr clauses) (cons (parse-normal-field fc) acc))])])))

     ;; Check if a raw-field-info item is a case-block entry
     (define (case-block-entry? item)
       (and (pair? item) (eq? (car item) 'case-block)))

     ;; If #:alignment is set, insert auto-alignment padding before each
     ;; non-first, non-padding field.
     (define align-injected-infos
       (if (attribute default-align)
           (let ([align-n (syntax-e #'default-align)])
             (let loop ([infos raw-field-infos] [first? #t] [acc '()])
               (cond
                 [(null? infos) (reverse acc)]
                 [(and (not first?)
                       (not (case-block-entry? (car infos)))
                       (not (eq? (syntax-e (second (car infos))) 'padding)))
                  ;; Insert an auto-align padding entry before this field
                  (define pad-name (datum->syntax (first (car infos))
                                                  (string->symbol
                                                   (format "__align_~a" (length acc)))))
                  (define pad-info
                    (list pad-name
                          (datum->syntax #f 'padding)
                          #f #f #f #f #f #f align-n #f #f #f))
                  (loop (cdr infos) #f (cons (car infos) (cons pad-info acc)))]
                 [else
                  (loop (cdr infos) #f (cons (car infos) acc))])))
           raw-field-infos))

     ;; Resolve #:align padding widths based on static offsets.
     ;; Walks fields, tracks byte offset, computes padding for #:align fields.
     (define field-infos
       (let loop ([infos align-injected-infos] [byte-off 0] [bit-acc 0] [acc '()])
         (cond
           [(null? infos)
            (reverse acc)]
           ;; Case blocks: pass through unchanged
           [(case-block-entry? (car infos))
            (loop (cdr infos) byte-off bit-acc (cons (car infos) acc))]
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
                                     #f #f #f #f #f #f #f #f #f)])
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
           ;; Embedded struct: convert to octets with runtime width
           [(and (pair? (second (car infos)))
                 (eq? (car (second (car infos))) 'embedded))
            (define info (car infos))
            (define struct-name-stx (cadr (second info)))
            (define resolved-info
              (list (first info)
                    (datum->syntax #f 'octets)
                    #`(protocol-desc-total-size #,struct-name-stx)
                    #f #f #f #f #f #f #f #f
                    (list 'embedded-struct struct-name-stx)))
            (loop (cdr infos) byte-off bit-acc (cons resolved-info acc))]
           ;; Repeated struct: mark as variable-length octets
           [(and (pair? (second (car infos)))
                 (eq? (car (second (car infos))) 'repeated-struct))
            (define info (car infos))
            (define marker (list-ref info 11))
            (define struct-name-stx (second marker))
            (define repeat-stx (third marker))
            ;; Store as octets with variable width based on count × struct size
            ;; For variable-size inner structs, use compute from the actual data
            ;; For the fd-expr width, use field-ref for the count.
            ;; The actual bytes-consumed is computed at decode time by the accessor.
            ;; For encode, we just need the total length of the concatenated bytes.
            ;; Width for this field: count × inner-struct-size
            ;; For self-referencing types, the struct-name reference is resolved lazily
            ;; at runtime (inside the lambda), after the define completes.
            (define width-expr-stx
              (syntax-parse repeat-stx
                [((~datum field-ref) ref-name:id)
                 #`(make-compute '(* (field-ref ref-name) struct-size)
                     (λ (lk) (* (lk 'ref-name)
                                (protocol-desc-total-size #,struct-name-stx))))]
                [n:nat
                 #`(* n (protocol-desc-total-size #,struct-name-stx))]))
            (define resolved-info
              (list (first info)
                    (datum->syntax #f 'octets)
                    width-expr-stx
                    #f #f #f #f #f #f #f #f
                    (list 'repeated-struct struct-name-stx repeat-stx)))
            (loop (cdr infos) byte-off bit-acc (cons resolved-info acc))]
           ;; Normal byte field
           [else
            (define info (car infos))
            (define flush-bytes (if (> bit-acc 0) (quotient bit-acc 8) 0))
            (define w (if (third info) (if (nat-stx? (third info)) (syntax-e (third info)) 0) 0))
            (loop (cdr infos) (+ byte-off flush-bytes w) 0 (cons info acc))])))

     ;; Separate normal field-infos from case blocks.
     ;; Flatten all field names (including case branch fields) for accessor/keyword generation.
     (define normal-field-infos
       (filter (λ (i) (not (case-block-entry? i))) field-infos))

     ;; All case-block entries
     (define case-block-entries
       (filter case-block-entry? field-infos))

     ;; Collect all field-infos from case branches (for accessor/keyword generation)
     (define case-branch-field-infos
       (apply append
              (for/list ([cb case-block-entries])
                (apply append
                       (for/list ([br (third cb)])
                         (second br))))))

     ;; All field infos (normal + case branch) for accessor/keyword purposes
     ;; Deduplicate by field name (same name in multiple branches → keep first)
     (define all-field-infos
       (let loop ([infos (append normal-field-infos case-branch-field-infos)]
                  [seen '()] [acc '()])
         (cond
           [(null? infos) (reverse acc)]
           [(memq (syntax-e (first (car infos))) seen)
            (loop (cdr infos) seen acc)]
           [else
            (loop (cdr infos)
                  (cons (syntax-e (first (car infos))) seen)
                  (cons (car infos) acc))])))

     ;; Use all-field-infos for name/keyword extraction
     (define field-names  (map first all-field-infos))

     ;; Determine if a field has a variable-length width (not a literal nat)
     (define (variable-width? info)
       (define w (third info))
       (and w (not (let ([v (syntax-e w)]) (and (integer? v) (exact? v) (>= v 0))))))

     (define (field-conditional? info)
       (and (>= (length info) 10) (tenth info) #t))

     ;; Check if a field is a repeated-struct
     (define (field-repeated-struct? info)
       (define v11 (and (>= (length info) 12) (list-ref info 11)))
       (define v1 (second info))
       (or (and (pair? v11) (eq? (car v11) 'repeated-struct))
           (and (pair? v1) (eq? (car v1) 'repeated-struct))))

     ;; Protocols with case blocks or repeated-structs use full-decode accessors
     (define has-case-or-repeated?
       (or (pair? case-block-entries)
           (ormap field-repeated-struct? all-field-infos)))

     ;; Case blocks and repeated-structs always make the protocol variable-length
     (define has-variable-fields?
       (or has-case-or-repeated?
           (ormap (λ (info) (or (variable-width? info) (field-conditional? info)))
                  normal-field-infos)))

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
       (and (>= (length info) 7) (seventh info) #t))

     (define (field-padding? info)
       (and (not (case-block-entry? info))
            (syntax? (second info))
            (eq? (syntax-e (second info)) 'padding)))

     ;; Helper: generate a make-field-desc expression from a field-info
     (define (info->fd-expr info)
         (define fn (first info))
         (define ft (second info))
         (define fw-stx (third info))
         (define fb (fourth info))
         (define fu (fifth info))
         (define fbi (sixth info))
         (define fc (seventh info))
         (define fk (eighth info))
         (define fp (tenth info))
         (define bo-expr (if fb #`'#,fb #`'default-bo))
         ;; Handle embedded/repeated-struct: use octets with placeholder width
         (define effective-ft
           (cond
             [(and (pair? ft) (eq? (car ft) 'embedded)) (datum->syntax #f 'octets)]
             [(and (pair? ft) (eq? (car ft) 'repeated-struct)) (datum->syntax #f 'octets)]
             [else ft]))
         (define width-arg
           (cond
             [(not fw-stx)
              ;; Embedded/repeated struct — compute width at runtime
              (cond
                [(and (pair? ft) (eq? (car ft) 'embedded))
                 (define struct-name (cadr ft))
                 ;; Width compute that works for both encode (bytes in hash)
                 ;; and decode (data buffer + offset)
                 #`(make-compute '(struct-size)
                     (λ (lk)
                       (define data (lk '#:data))
                       (define off (lk '#:offset))
                       (if (and data off)
                           ;; Decode path: compute from data buffer
                           (protocol-desc-total-size-at data off #,struct-name)
                           ;; Encode path: get from pre-encoded bytes in hash
                           (let ([v (lk '#,fn)])
                             (if (bytes? v) (bytes-length v) 0)))))]
                [(and (pair? ft) (eq? (car ft) 'repeated-struct))
                 ;; For repeated structs, width per element × count
                 ;; Width is the full block — handled by accessor
                 #'1]
                [else #'1])]
             [else (width-stx->expr fw-stx)]))
         (define effective-bito
           (or fbi (and (attribute default-bito) #'default-bito)))
         (define kw-args
           (append (if fu (list #'#:unit #`'#,fu) '())
                   (if effective-bito (list #'#:bit-order #`'#,effective-bito) '())
                   (if fc (list #'#:compute fc) '())
                   (if fk (list #'#:contract fk) '())
                   (if fp (list #'#:present-when fp) '())))
         #`(make-field-desc '#,fn '#,effective-ft #,width-arg #,bo-expr #,@kw-args))

     ;; Protocol field list: mix of make-field-desc and make-case-block exprs
     (define fd-exprs
       (for/list ([info field-infos])
         (if (case-block-entry? info)
             ;; Generate make-case-block expression
             (let ([disc-name (second info)]
                   [branches (third info)])
               #`(make-case-block '#,disc-name
                   (list #,@(for/list ([br branches])
                              (define pred-stx (first br))
                              (define branch-infos (second br))
                              #`(make-case-branch
                                 #,pred-stx
                                 (list #,@(map info->fd-expr branch-infos)))))))
             ;; Normal field-desc
             (info->fd-expr info))))

     ;; Track which all-field-infos indices are from case branches (always optional)
     (define case-branch-field-indices
       (let ([n (length normal-field-infos)])
         (for/list ([i (in-range n (length all-field-infos))])
           i)))

     (define (case-branch-field? idx)
       (memv idx case-branch-field-indices))

     ;; Encode function formals: exclude computed and padding fields from keyword args
     (define (field-has-default? info)
       (and (>= (length info) 11) (list-ref info 10) #t))

     (define encode-sorted-idxs
       (filter (λ (i) (define info (list-ref all-field-infos i))
                       (not (or (field-computed? info) (field-padding? info))))
               sorted-idxs))

     (define encode-sorted-params
       (for/list ([i encode-sorted-idxs])
         (generate-temporary (list-ref field-names i))))

     ;; Build formals: required kw args first, then optional (with defaults)
     ;; Actually Racket allows intermixed optional/required in sorted order
     (define encode-formals
       (apply append
              (for/list ([i encode-sorted-idxs]
                         [param encode-sorted-params])
                (define info (list-ref all-field-infos i))
                (define kw (datum->syntax #'sname (list-ref field-kws i)))
                (cond
                  [(case-branch-field? i)
                   ;; Case branch fields are always optional with default #f
                   (list kw (list param #'#f))]
                  [(field-has-default? info)
                   (list kw (list param (list-ref info 10)))]
                  [else
                   (list kw param)]))))

     (define encode-hash-pairs
       (apply append
              (for/list ([i encode-sorted-idxs]
                         [param encode-sorted-params])
                (define fn (list-ref field-names i))
                (define info (list-ref all-field-infos i))
                (define fenum (and (>= (length info) 12) (list-ref info 11)))
                (cond
                  ;; Repeated struct: concatenate list of bytes
                  [(and (pair? fenum) (eq? (car fenum) 'repeated-struct))
                   (list #`'#,fn #`(apply bytes-append #,param))]
                  ;; Enum transform
                  [(and fenum (not (pair? fenum)))
                   (list #`'#,fn #`(wire-enum-ref #,fenum #,param))]
                  [else
                   (list #`'#,fn param)]))))

     ;; Helper: is this an embedded struct field?
     (define (field-embedded-struct? info)
       (define v11 (and (>= (length info) 12) (list-ref info 11)))
       (define v1 (second info))
       (or (and (pair? v11) (eq? (car v11) 'embedded-struct))
           (and (pair? v1) (eq? (car v1) 'embedded))))

     (define (field-embedded-struct-name info)
       (define v11 (and (>= (length info) 12) (list-ref info 11)))
       (define v1 (second info))
       (cond
         [(and (pair? v11) (eq? (car v11) 'embedded-struct)) (cadr v11)]
         [(and (pair? v1) (eq? (car v1) 'embedded)) (cadr v1)]
         [else #f]))

     ;; Helper: wrap an accessor body expr with enum lookup if needed
     (define (maybe-wrap-enum info body-expr)
       (define fenum (list-ref info 11))
       (if (and fenum (not (pair? fenum)))  ;; not an embedded-struct marker
           #`(wire-enum-lookup #,fenum #,body-expr)
           body-expr))

     ;; Helper: wrap accessor for embedded struct (decode bytes as inner struct)
     (define (maybe-wrap-embedded info body-expr)
       (if (field-embedded-struct? info)
           (let ([struct-name (field-embedded-struct-name info)])
             (define decode-fn (format-id struct-name "~a-decode" struct-name))
             #`(let ([raw #,body-expr])
                 (if (bytes? raw)
                     (#,decode-fn raw)
                     raw)))
           body-expr))

     ;; Combined accessor wrapper
     (define (wrap-accessor info body-expr)
       (maybe-wrap-enum info (maybe-wrap-embedded info body-expr)))

     ;; Generate accessor defs for case-block/repeated-struct protocols
     (define (make-case-accessor-defs)
       (for/list ([aid accessor-ids]
                  [fn field-names]
                  [info all-field-infos]
                  #:unless (field-padding? info))
         (if (field-repeated-struct? info)
             ;; Repeated struct: custom accessor using decode-repeated-struct
             ;; The hash-ref approach won't work because the codec can't decode these.
             ;; Instead, we compute the offset of this field and decode in place.
             (let* ([marker (list-ref info 11)]
                    [struct-name (second marker)]
                    [repeat-expr (third marker)]
                    [decode-fn (format-id struct-name "~a-decode" struct-name)])
               #`(define (#,aid v)
                   ;; Decode the protocol to get the count value and find offset
                   (define decoded (decode #,desc-id (#,inst-bytes v)
                                          #:offset (#,inst-offset v)))
                   (define count
                     #,(syntax-parse repeat-expr
                         [((~datum field-ref) ref-name:id)
                          #`(hash-ref decoded 'ref-name)]
                         [n:nat #'n]))
                   ;; Items offset = base + fixed portion size (which excludes variable fields)
                   (define items-offset
                     (+ (#,inst-offset v) (protocol-desc-total-size #,desc-id)))
                   (define-values (items _)
                     (decode-repeated-struct
                      (#,inst-bytes v) items-offset count
                      #,decode-fn
                      (λ (data offset)
                        (protocol-desc-total-size-at data offset #,struct-name))))
                   items))
             ;; Normal field: decode + hash-ref
             #`(define (#,aid v)
                 (define decoded (decode #,desc-id (#,inst-bytes v)
                                        #:offset (#,inst-offset v)))
                 (define raw-val (hash-ref decoded '#,fn #f))
                 #,(wrap-accessor info #'raw-val)))))

     ;; Generate accessor defs for dynamic (variable-length, no case blocks)
     (define (make-dynamic-accessor-defs)
       (for/list ([aid accessor-ids]
                  [fn field-names]
                  [info all-field-infos]
                  [idx (range (length all-field-infos))]
                  #:unless (field-padding? info))
         (define ft (second info))
         #`(define (#,aid v)
             (define bounds (vector-ref (#,inst-bounds v) #,idx))
             (define raw-val
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
                                  #:bit-order (sixth bounds))]))
             #,(wrap-accessor info #'raw-val))))

     ;; Generate accessor defs for static (fixed-width, no case blocks)
     (define (make-static-accessor-defs)
       (for/list ([aid accessor-ids]
                  [fn field-names]
                  [info all-field-infos]
                  [ai static-accessor-infos]
                  #:unless (field-padding? info))
         (define ft (second info))
         (case (car ai)
           [(byte)
            (define byte-off (second ai))
            #`(define (#,aid v)
                (define raw-val
                  (decode-field (#,inst-bytes v)
                                (+ (#,inst-offset v) #,byte-off)
                                (protocol-desc-field-ref #,desc-id '#,fn)))
                #,(wrap-accessor info #'raw-val))]
           [(bits)
            (define group-byte-off (second ai))
            (define group-bytes (third ai))
            (define bit-offset (fourth ai))
            (define bit-width (fifth ai))
            (define bit-ord (sixth ai))
            #`(define (#,aid v)
                (define raw-val
                  (decode-bitfield (#,inst-bytes v)
                                   (+ (#,inst-offset v) #,group-byte-off)
                                   #,group-bytes
                                   #,bit-offset
                                   #,bit-width
                                   '#,ft
                                   #:bit-order '#,(datum->syntax #'sname bit-ord)))
                #,(wrap-accessor info #'raw-val))])))

     ;; Select accessor strategy
     (define accessor-defs
       (cond
         [has-case-or-repeated? (make-case-accessor-defs)]
         [has-variable-fields? (make-dynamic-accessor-defs)]
         [else (make-static-accessor-defs)]))


     ;; Accessor table for match expander (skip padding)
     (define accessor-table-for-match
       (for/list ([fn field-names]
                  [aid accessor-ids]
                  [info all-field-infos]
                  #:unless (field-padding? info))
         (cons (symbol->string (syntax-e fn)) aid)))

     #`(begin
         ;; Instance struct
         #,(if (and has-variable-fields? (not has-case-or-repeated?))
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
         #,(cond
             [has-case-or-repeated?
              ;; Case-block/repeated-struct protocols: no boundaries needed
              #`(define (#,decode-id data #:offset [offset 0])
                  (#,instance-id data offset))]
             [has-variable-fields?
              #`(define (#,decode-id data #:offset [offset 0])
                  (define bounds (compute-field-boundaries #,desc-id data offset))
                  (#,instance-id data offset bounds))]
             [else
              #`(define (#,decode-id data #:offset [offset 0])
                  (#,instance-id data offset))])

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
