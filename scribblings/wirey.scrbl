#lang scribble/manual

@require[@for-label[wirey
                    wirey/field
                    wirey/protocol
                    wirey/codec
                    wirey/syntax
                    wirey/length-expr
                    wirey/stack
                    wirey/dispatch
                    wirey/checksum
                    wirey/enum
                    racket/base
                    racket/match]]

@title{wirey: Binary Wire Protocol Specifications}
@author{sbj}

@defmodule[wirey]

Wirey is a Racket-native DSL for declaratively specifying binary wire
protocols. Inspired by ACN (ASN.1 Control Notation), it provides both a
data-driven description layer and a macro surface syntax for defining wire
structures with automatic generation of encoders, decoders, field accessors,
and match expanders.

@bold{Key capabilities:}

@itemlist[
  @item{@bold{struct/wire} — define binary layouts with keyword encode,
    zero-copy decode, and pattern matching}
  @item{@bold{Bitfields} — sub-byte fields with MSB/LSB bit ordering}
  @item{@bold{Variable-length fields} — widths dependent on other fields}
  @item{@bold{Protocol composition} — layered decode with dispatch
    (Ethernet → IPv4 → TCP)}
  @item{@bold{Message dispatch} — route bytes to the correct wire struct
    by discriminator field}
  @item{@bold{Computed fields} — auto-computed checksums via two-pass encoding}
  @item{@bold{Rich type system} — uint, sint, float32/64, bcd, bool,
    alpha, utf8, utf16, utf32, octets, padding}
  @item{@bold{Contracts, enums, defaults, arrays, conditional fields,
    alignment, embedded structs}}
]

@table-of-contents[]

@; ------------------------------------------------------------------
@section{Quick Start}

@racketblock[
(require wirey racket/match)

(struct/wire udp-header
  #:byte-order big
  (src-port   uint 2)
  (dst-port   uint 2)
  (length     uint 2)
  (checksum   uint 2))

(code:comment "Encode with keyword arguments")
(define pkt
  (udp-header-encode
   #:src-port  49152
   #:dst-port  53
   #:length    42
   #:checksum  0))

(code:comment "Decode to a wire struct, access fields by name")
(define hdr (udp-header-decode pkt))
(udp-header-src-port hdr)
(udp-header-dst-port hdr)

(code:comment "Pattern match on specific fields")
(match hdr
  [(udp-header #:dst-port dp #:src-port sp)
   (printf "~a → ~a\n" sp dp)])
]

@; ------------------------------------------------------------------
@section{Wire Structures}

@defmodule[wirey/syntax]

@defform[(struct/wire name
           maybe-byte-order
           maybe-bit-order
           maybe-alignment
           field-spec ...)
         #:grammar
         ([maybe-byte-order (code:line)
                            (code:line #:byte-order byte-order-id)]
          [maybe-bit-order (code:line)
                           (code:line #:bit-order bit-order-id)]
          [maybe-alignment (code:line)
                           (code:line #:alignment nat)]
          [field-spec (field-name type-id width-expr field-option ...)
                      (field-name type-id #:align nat)
                      (field-name struct-name #:struct)]
          [field-option (code:line #:byte-order byte-order-id)
                        (code:line #:unit unit-id)
                        (code:line #:bit-order bit-order-id)
                        (code:line #:compute expr)
                        (code:line #:contract expr)
                        (code:line #:present-when expr)
                        (code:line #:default expr)
                        (code:line #:enum expr)
                        (code:line #:terminator nat)
                        (code:line #:repeat expr)
                        (code:line #:repeat-until expr)])]{

Defines a binary wire structure and introduces:

@itemlist[
  @item{@racketvarfont{name} — a @racket[protocol-desc] value (also a
    @racket[match] expander)}
  @item{@racketvarfont{name}@racketidfont{?} — predicate}
  @item{@racketvarfont{name}@racketidfont{-encode} — keyword args → @racket[bytes]}
  @item{@racketvarfont{name}@racketidfont{-decode} — @racket[bytes] → wire struct
    instance (zero-copy)}
  @item{@racketvarfont{name}@racketidfont{-}@racketvarfont{field} — accessor per
    non-padding field}
]}

@subsection{Field Types}

@tabular[#:style 'boxed
         #:column-properties '(left left left)
         (list (list @bold{Type} @bold{Width} @bold{Description})
               (list @racket[uint] "N bytes" "Unsigned integer")
               (list @racket[sint] "N bytes" "Signed two's complement")
               (list @racket[alpha] "N bytes" "ASCII, space-padded (or null-terminated with #:terminator)")
               (list @racket[octets] "N bytes" "Raw bytes")
               (list @racket[float32] "4 bytes" "IEEE 754 single-precision")
               (list @racket[float64] "8 bytes" "IEEE 754 double-precision")
               (list @racket[bcd] "N bytes" "Packed BCD (two digits per byte)")
               (list @racket[bool] "1 byte"  "Boolean: 0 = #f, nonzero = #t")
               (list @racket[utf8] "N bytes" "UTF-8 string, null-padded")
               (list @racket[utf16] "N bytes" "UTF-16 string, byte-order aware")
               (list @racket[utf32] "N bytes" "UTF-32 string, byte-order aware")
               (list @racket[padding] "N bytes" "Zero bytes, skipped on decode"))]

@subsection{Bitfields}

Fields can be specified in bits rather than bytes using @racket[#:unit bits]:

@racketblock[
(struct/wire ipv4-header
  #:byte-order big
  (version          uint 4  #:unit bits)
  (ihl              uint 4  #:unit bits)
  (dscp             uint 6  #:unit bits)
  (ecn              uint 2  #:unit bits)
  (total-length     uint 2)
  ...)
]

Contiguous bitfields form a group that must sum to a whole number of bytes.
Bit ordering defaults to MSB-first but can be overridden with
@racket[#:bit-order lsb] at the protocol, group, or field level.

@subsection{Variable-Length Fields}

A field's width can depend on another field's value:

@racketblock[
(struct/wire pcap-packet
  #:byte-order little
  (ts-sec    uint   4)
  (ts-usec   uint   4)
  (incl-len  uint   4)
  (orig-len  uint   4)
  (data      octets (field-ref incl-len)))
]

Use @racket[(compute expr)] for arithmetic on field references:

@racketblock[
(options octets (compute (* (- (field-ref ihl) 5) 4)))
]

@subsection{Computed Fields}

Fields with @racket[#:compute] are auto-calculated during encoding.
The compute function receives the encoded buffer (with the field zeroed)
and returns the field's value. Computed fields are omitted from encode
keyword arguments.

@racketblock[
(struct/wire checksummed-msg
  #:byte-order big
  (data           uint 4)
  (header-checksum uint 2 #:compute ipv4-header-checksum))
]

@subsection{Conditional Fields}

Fields with @racket[#:present-when] are included only when the predicate
returns true. The predicate receives a lookup function over already-decoded
field values. Absent fields decode as @racket[#f].

@racketblock[
(struct/wire optional-msg
  #:byte-order big
  (flags   uint 1)
  (payload uint 4 #:present-when (λ (lk) (> (lk 'flags) 0))))
]

@subsection{Contracts}

@racket[#:contract] attaches a predicate checked at encode time:

@racketblock[
(struct/wire validated-msg
  #:byte-order big
  (port uint 2 #:contract (λ (v) (<= 0 v 65535)))
  (ttl  uint 1 #:contract (λ (v) (> v 0))))
]

@subsection{Default Values}

Fields with @racket[#:default] become optional keyword arguments:

@racketblock[
(struct/wire ipv4-header
  #:byte-order big
  (version uint 4 #:unit bits #:default 4)
  (ihl     uint 4 #:unit bits #:default 5)
  ...)

(code:comment "version and ihl can be omitted:")
(ipv4-header-encode #:total-length 1500 ...)
]

@subsection{Enums}

@racket[#:enum] auto-converts between symbols and integers:

@racketblock[
(define-wire-enum ip-protocol
  [tcp 6] [udp 17] [icmp 1])

(struct/wire ipv4-header
  #:byte-order big
  ...
  (protocol uint 1 #:enum ip-protocol)
  ...)

(code:comment "Encode with symbol:")
(ipv4-header-encode ... #:protocol 'tcp ...)

(code:comment "Decode returns symbol:")
(ipv4-header-protocol hdr) (code:comment "'tcp")
]

@subsection{Repetition}

@racket[#:repeat] creates array fields. The count can be a fixed number
or a @racket[field-ref]:

@racketblock[
(struct/wire array-msg
  #:byte-order big
  (count uint 1)
  (items uint 2 #:repeat (field-ref count)))
]

@racket[#:repeat-until] reads elements until a sentinel predicate matches:

@racketblock[
(struct/wire sentinel-msg
  #:byte-order big
  (items uint 2 #:repeat-until (λ (v) (= v 0))))
]

@subsection{Padding and Alignment}

Explicit padding fields encode as zeros and generate no accessor:

@racketblock[
(struct/wire padded
  #:byte-order big
  (tag uint 1)
  (pad padding 3)
  (val uint 4))
]

@racket[(padding #:align N)] auto-computes padding to reach an N-byte boundary.
@racket[#:alignment N] on the protocol inserts alignment padding before each field:

@racketblock[
(struct/wire aligned
  #:byte-order big
  #:alignment 4
  (tag   uint 1)
  (value uint 4)
  (short uint 2)
  (data  uint 4))
]

@subsection{Embedded Structs}

A field can embed another wire struct using @racket[#:struct]:

@racketblock[
(struct/wire inner-hdr
  #:byte-order big
  (tag uint 1) (len uint 2))

(struct/wire outer-msg
  #:byte-order big
  (header inner-hdr #:struct)
  (data   uint 4))

(code:comment "Encode: pass pre-encoded bytes")
(outer-msg-encode #:header (inner-hdr-encode #:tag 1 #:len 4)
                  #:data #xDEADBEEF)

(code:comment "Decode: accessor returns inner struct instance")
(inner-hdr-tag (outer-msg-header (outer-msg-decode bs)))
]

@subsection{Null-Terminated Strings}

@racket[#:terminator] on string fields specifies a terminator byte:

@racketblock[
(struct/wire c-string-msg
  #:byte-order big
  (name alpha 256 #:terminator 0))
]

@; ------------------------------------------------------------------
@section{Protocol Composition}

@defmodule[wirey/stack]

@defform[(define-stack name
           wire-struct
           #:dispatch field-name
           [(value) wire-struct optional-dispatch ...] ...)]{

Defines a layered protocol stack with field-value dispatch. Each layer
is decoded at the current offset, then the dispatch field's value
determines which wire struct to decode next.

@racketblock[
(define-stack ethernet/ip-stack
  ethernet-header
  #:dispatch ethertype
  [(#x0800)
   ipv4-header
   #:dispatch protocol
   [(6)  tcp-header]
   [(17) udp-header]])

(define result (ethernet/ip-stack-decode packet-bytes))
(define ip (stack-ref result ipv4-header?))
(ipv4-header-src-ip ip)
]}

@defproc[(stack-ref [sv stack-value?] [pred (-> any/c boolean?)]) any/c]{
Finds a decoded layer instance by predicate, or @racket[#f].}

@; ------------------------------------------------------------------
@section{Message Dispatch}

@defmodule[wirey/dispatch]

@defform[(define-dispatch name
           #:offset nat
           #:width nat
           #:type type-id
           [(value) wire-struct] ...)]{

Defines a discriminator-based message dispatch. Reads a field at the
specified offset/width, looks up the wire struct in an O(1) hash table,
and decodes the full message. Returns @racket[#f] for unknown values.

@racketblock[
(define-dispatch itch-message
  #:offset 0
  #:width  1
  #:type   alpha
  [("S") itch-system-event]
  [("A") itch-add-order]
  [("P") itch-trade])

(match (itch-message-decode raw-bytes)
  [(itch-add-order #:stock sym #:price p)
   (printf "Order: ~a @ ~a\n" sym p)]
  [(itch-trade #:stock sym #:price p)
   (printf "Trade: ~a @ ~a\n" sym p)])
]}

@; ------------------------------------------------------------------
@section{Checksums}

@defmodule[wirey/checksum]

@defproc[(internet-checksum [data bytes?]) exact-nonneg-integer?]{
Computes the RFC 1071 internet checksum: the one's complement of the
one's complement sum of 16-bit words. Returns a 16-bit value.}

@defproc[(ipv4-header-checksum [header-bytes bytes?]) exact-nonneg-integer?]{
Computes the IPv4 header checksum. The checksum field (bytes 10--11)
should be zeroed in the input.}

@; ------------------------------------------------------------------
@section{Enumerated Types}

@defmodule[wirey/enum]

@defform[(define-wire-enum name [symbol value] ...)]{
Defines a bidirectional mapping between symbols and integer values.}

@defproc[(wire-enum? [v any/c]) boolean?]{
Returns @racket[#t] if @racket[v] is a wire enum.}

@defproc[(wire-enum-ref [we wire-enum?] [val (or/c symbol? integer?)]) integer?]{
Resolves a value for encoding: symbols are mapped to integers,
integers pass through.}

@defproc[(wire-enum-lookup [we wire-enum?] [val integer?]) (or/c symbol? integer?)]{
Resolves a value for decoding: known integers are mapped to symbols,
unknown integers pass through.}

@; ------------------------------------------------------------------
@section{Length Expressions}

@defmodule[wirey/length-expr]

Length expressions describe variable field widths.

@defproc[(make-field-ref [name symbol?]) field-ref?]{
Creates a length expression that references another field's decoded value.}

@defproc[(make-compute [source any/c] [fn (-> (-> symbol? any/c) any/c)]) compute?]{
Creates a length expression computed from a function over field values.
The function receives a lookup procedure @racket[(symbol? -> any/c)].}

@defproc[(eval-length-expr [expr length-expr?] [lookup (-> symbol? any/c)]) exact-nonneg-integer?]{
Evaluates a length expression given a field lookup function.}

@; ------------------------------------------------------------------
@section{Data-Driven Layer}

@subsection{Field Descriptors}

@defmodule[wirey/field]

@defproc[(make-field-desc [name symbol?]
                          [type field-type?]
                          [width (or/c exact-positive-integer? field-ref? compute?)]
                          [byte-order byte-order?]
                          [#:unit unit field-unit? 'bytes]
                          [#:bit-order bit-order (or/c bit-order? #f) #f]
                          [#:compute compute-fn (or/c procedure? #f) #f]
                          [#:contract contract-fn (or/c procedure? #f) #f]
                          [#:present-when present-fn (or/c procedure? #f) #f]
                          [#:terminator term (or/c exact-nonneg-integer? #f) #f]
                          [#:repeat repeat-count (or/c exact-positive-integer? field-ref? #f) #f]
                          [#:repeat-until repeat-pred (or/c procedure? #f) #f])
         field-desc?]{
Creates a field descriptor with full control over all field options.}

@subsection{Protocol Descriptors}

@defmodule[wirey/protocol]

@defproc[(make-protocol-desc [name symbol?]
                             [fields (listof field-desc?)])
         protocol-desc?]{
Creates a protocol descriptor. Validates bitfield groups sum to whole bytes
and variable-length field references are valid.}

@defproc[(protocol-desc-total-size [pd protocol-desc?]) exact-nonneg-integer?]{
Total fixed-portion size in bytes. Variable-length and conditional fields
are excluded.}

@subsection{Codec}

@defmodule[wirey/codec]

@defproc[(encode [pd protocol-desc?]
                 [values (hash/c symbol? any/c)])
         bytes?]{
Encodes values according to the protocol descriptor. Handles bitfields,
variable-length fields, computed fields (two-pass), conditional fields,
repeated fields, and contract validation.}

@defproc[(decode [pd protocol-desc?]
                 [data bytes?]
                 [#:offset offset exact-nonneg-integer? 0])
         (hash/c symbol? any/c)]{
Decodes data according to the protocol descriptor. Handles all field
types including conditional (absent → @racket[#f]) and repeated
(→ list) fields.}

@; ------------------------------------------------------------------
@section{Bundled Protocols}

@subsection{ITCH 5.0}
@defmodule[wirey/protocols/itch]

NASDAQ TotalView-ITCH 5.0 messages (big-endian):
@racket[itch-system-event], @racket[itch-add-order],
@racket[itch-add-order-mpid], @racket[itch-order-executed],
@racket[itch-order-delete], @racket[itch-trade].

@subsection{Network Headers}
@defmodule[wirey/protocols/ipv4]
@racket[ipv4-header] — 20-byte IPv4 header with bitfields.

@defmodule[wirey/protocols/tcp]
@racket[tcp-header] — 20-byte TCP header with flag bitfields.

@defmodule[wirey/protocols/udp]
@racket[udp-header] — 8-byte UDP header.

@defmodule[wirey/protocols/ethernet]
@racket[ethernet-header] — 14-byte Ethernet frame header.

@subsection{PCAP}
@defmodule[wirey/protocols/pcap]
@racket[pcap-global-header] (24 bytes),
@racket[pcap-record-header] (16 bytes),
@racket[pcap-packet] (header + variable-length data).

@subsection{Protocol Stacks}
@defmodule[wirey/protocols/stacks]
@racket[ethernet/ip-stack] — Ethernet → IPv4 → TCP/UDP.

@; ------------------------------------------------------------------
@section{Scope and Limitations}

Wirey targets @bold{fixed-layout and semi-fixed-layout} binary protocols:
formats where the structure is determined by header fields and can be
described as a flat sequence of fields with conditional presence,
variable lengths, and dispatch tables.

Wirey @bold{does not} target self-describing recursive formats such as
CBOR, ASN.1 BER/DER, Protocol Buffers, or MessagePack. These formats
require recursive type definitions, N-way conditional structures within
a single message, and variable-width self-describing integer encodings
that are beyond wirey's flat field model.

Protocols well-suited to wirey include:
ITCH, FIX/FAST, Ethernet/IPv4/TCP/UDP, PCAP, DNS (headers),
USB descriptors, Bluetooth HCI, SPI/I2C register maps,
and most hardware-oriented binary formats.
