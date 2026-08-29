# encoding: UTF-8

control 'C-4.12' do
  title 'Ensure all signed artifacts are validated'
  desc  "
    Validate artifacts signatures before uploading to the package registry.

    Cryptographic signature is a tool to verify artifact authenticity. Every artifact is supposed to be signed by its creator in order to verify that it wasn't compromised until it got to the client. Validating artifact signature before delivering it is another level of protection, which checks that the signature hasn't been changed, which means that no one tried or succeeded in tampering with the artifact. That sets trust between the supplier and the client.
  "
  desc  'rationale', "
    Validate artifacts signatures before uploading to the package registry.

    Cryptographic signature is a tool to verify artifact authenticity. Every artifact is supposed to be signed by its creator in order to verify that it wasn't compromised until it got to the client. Validating artifact signature before delivering it is another level of protection, which checks that the signature hasn't been changed, which means that no one tried or succeeded in tampering with the artifact. That sets trust between the supplier and the client.
  "
  desc  'check', "
    Ensure every artifact in the package has been validated with its signature.
  "
  desc  'fix', "
    Validate every artifact with its signature. It is recommended to do so automatically.
  "
  impact 0.5
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['SI-7 a']
  tag cci:                   ['CCI-002704']
  tag cis_number:            '4.12'
  tag cis_rid:               '4.12'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-0412r1_rule'
  tag cis_version:           '1.8.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'alternative'
  tag attestation_category:  'policy'
  tag exec_validated:        false

  uri = input('c_4_12_attestation_uri', value: '')
  uri = attestation_uri(:boundary, 'C-4.12') if uri.to_s.empty?
  if uri.to_s.empty?
    describe 'Requires manual review and attestation' do
      skip "Requires manual review and attestation provided for this control (signed-artifact validation is supply-chain pipeline scope (cosign / sigstore / Notary); operators attest from their signing pipeline) [Lift: set boundary_docs_base / c_4_12_attestation_uri, or `saf attest apply`.]"
    end
  else
    doc = document_attestation(uri, max_age_days: input('attestation_max_age_days', value: 365))
    describe "Boundary policy attestation (C-4.12) (#{uri})" do
      it('reachable') { expect(doc.connection_error).to be_nil, "attestation unreachable: #{doc.connection_error}" }
      it('exists') { expect(doc.exists?).to eq(true) }
      it("current") { expect(doc.current?).to eq(true) }
    end
  end
end
