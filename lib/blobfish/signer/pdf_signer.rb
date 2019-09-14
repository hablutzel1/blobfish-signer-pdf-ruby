require 'origami'
include Origami

module Blobfish
  module Signer
    class PdfSigner

      def self.verify (signed_file, trusted_anchors: [])
        pdf = PDF.read signed_file, {verbosity: Origami::Parser::VERBOSE_QUIET}
        validation_results = []
        # Based on Origami::PDF#signature. TODO patch origami to support multiple signatures validation.
        pdf.each_field do |field|
          if field.FT == :Sig and field.V.is_a?(Dictionary)
            val_result = {}
            val_result[:sig_name] = field.T.value
            digsig = field.V

            # Based on Origami::PDF#extract_signed_data, but it fails for multiple signatures in a PDF. TODO patch origami to support multiple signatures in a PDF.
            r1, r2 = digsig.ranges
            signed_data = pdf.original_data[r1] + pdf.original_data[r2]

            # Verify integrity.
            pkcs7 = OpenSSL::PKCS7.new(digsig[:Contents])
            # TODO check if this store can be totally omitted somehow.
            empty_store = OpenSSL::X509::Store.new
            # We provide OpenSSL::PKCS7::NOVERIFY to indicate explicitly that we don't want certificate verification in this step.
            integrity_valid = pkcs7.verify([], empty_store, signed_data, OpenSSL::PKCS7::DETACHED | OpenSSL::PKCS7::BINARY | OpenSSL::PKCS7::NOVERIFY)
            if integrity_valid
              pkcs7_certs = pkcs7.certificates

              # TODO look if OpenSSL for Ruby provides a simpler method to get the signer certificate from the PKCS #7 structure.
              pkcs7_signers = pkcs7.signers
              pkcs7_signer = pkcs7_signers[0]
              signer_cert = nil
              pkcs7_certs.each do |cert|
                if cert.issuer == pkcs7_signer.issuer && cert.serial == pkcs7_signer.serial
                  signer_cert = cert
                end
              end

              cpv_store = OpenSSL::X509::Store.new
              trusted_anchors.each {|trusted_anchor_file|
                ca = OpenSSL::X509::Certificate.new(File.read(trusted_anchor_file))
                cpv_store.add_cert(ca)
              }
              # TODO validate the certificate at the time of signing (or from the timestamp).
              # TODO check if we could support verifying from an intermediate CA (i.e. partial_chain).
              cpv_valid = cpv_store.verify(signer_cert, pkcs7_certs)
              if cpv_valid
                val_result[:chain] = cpv_store.chain
              else
                val_result[:error] = "Certificate validation failed"
              end

              # TODO verify revocation status.

            else
              val_result[:error] = "Integrity validation failed"
            end
            validation_results << val_result
          end
        end
        validation_results
      end

#       def self.sign
#         pdf = PDF.read 'sample_correct_signature.pdf'
# #
# # # puts "This document has #{pdf.pages.size} page(s)"
# #
# # pdf.each_page do |page|
# #   page.each_font do |name, font|
# #     # ... only parse the necessary bits
# #     zas = 3
# #   end
# # end
# #
# #
# # pdf = PDF.new
# # page = Page.new.setContents(contents)
# # pdf.append_page(page)
# #
#
#         page = pdf.get_page(1)
#         sig_annot = Annotation::Widget::Signature.new
#         sig_annot.Rect = Rectangle[llx: 0, lly: 0, urx: 0, ury: 0]
# # FIXME without creating the signature annotation and adding it explicitly to a page, Adobe recognizes that the document has signature buts fails to list the signature. See https://i.imgur.com/VtaCwqe.png.
#         page.add_annotation(sig_annot)
#
# # TODO extract cert and key from PFX.
#         ca2 = OpenSSL::X509::Certificate.new(File.read("blobfish_issuing_ca.cer"))
#         string = 'John_Doe_test_certificate.pfx'
#         file_open = File.open(string, 'rb')
#         file_read = file_open.read
#         pfx = OpenSSL::PKCS12.new(file_read, 'secret')
#         cert = OpenSSL::X509::Certificate.new(pfx.certificate)
#         p_key_rsa_new = OpenSSL::PKey::RSA.new(pfx.key)
#
# # Sign the PDF with the specified keys
#         pdf.sign(cert, p_key_rsa_new,
#                  method: 'adbe.pkcs7.detached',
#                  ca: [ca2],
#                  annotation: sig_annot,
#                  location: 'France',
#                  contact: 'gdelugre@localhost',
#                  reason: 'Signature sample'
#         )
#
# # Save the resulting file
#         pdf.save('sample_signed_2.pdf')
#       end

    end
  end
end