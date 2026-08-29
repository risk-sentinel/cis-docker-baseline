# encoding: UTF-8

control 'C-4.4' do
  title 'Ensure images are scanned and rebuilt to include security patches'
  desc  "
    Images should be scanned frequently for any vulnerabilities. You should rebuild all images to include these patches and then instantiate new containers from them.

    Vulnerabilities are loopholes or bugs that can be exploited by hackers or malicious users, and security patches are updates to resolve these vulnerabilities. Image vulnerability scanning tools can be use to find vulnerabilities in images and then check for available patches to mitigate these. Patches update the system to a more recent code base which does not contain these problems, and being on a supported version of the code base is very important, as vendors do not tend to supply patches for older versions which have gone out of support. Security patches should be evaluated before applying and patching should be implemented in line with the organization's IT Security Policy.

    Care should be taken with the results returned by vulnerability assessment tools, as some will simply return results based on software banners, and these may not be entirely accurate.
  "
  desc  'rationale', "
    Images should be scanned frequently for any vulnerabilities. You should rebuild all images to include these patches and then instantiate new containers from them.

    Vulnerabilities are loopholes or bugs that can be exploited by hackers or malicious users, and security patches are updates to resolve these vulnerabilities. Image vulnerability scanning tools can be use to find vulnerabilities in images and then check for available patches to mitigate these. Patches update the system to a more recent code base which does not contain these problems, and being on a supported version of the code base is very important, as vendors do not tend to supply patches for older versions which have gone out of support. Security patches should be evaluated before applying and patching should be implemented in line with the organization's IT Security Policy.

    Care should be taken with the results returned by vulnerability assessment tools, as some will simply return results based on software banners, and these may not be entirely accurate.
  "
  desc  'check', "
    List all the running instances of containers by executing the command below:
    ```
    docker ps --quiet 
    ```

    For each container instance, use the package manager within the container (assuming there is one available) to check for the availability of security patches.

    Alternatively, run image vulnerability assessment tools to scan all the images in your environment.
  "
  desc  'fix', "
    Images should be re-built ensuring that the latest version of the base images are used, to keep the operating system patch level at an appropriate level. Once the images have been re-built, containers should be re-started making use of the updated images.
  "
  impact 0.5
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['RA-5 a', 'CA-5 a']
  tag ksi:                   ['KSI-SCR-MON']
  tag nist_r4:               ['CA-5 a', 'RA-5 a']
  tag cci:                   ['CCI-001055', 'CCI-000264']
  tag cis_number:            '4.4'
  tag cis_rid:               '4.4'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-0404r1_rule'
  tag cis_version:           '1.8.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'alternative'
  tag attestation_category:  'policy'
  tag exec_validated:        false

  uri = input('c_4_4_attestation_uri', value: '')
  uri = attestation_uri(:boundary, 'C-4.4') if uri.to_s.empty?
  if uri.to_s.empty?
    describe 'Requires manual review and attestation' do
      skip "Requires manual review and attestation provided for this control (image scanning + rebuild cadence is a CI/CD pipeline concern (ECR scan, Trivy, Snyk, etc.) — operators attest from their pipeline scan results) [Lift: set boundary_docs_base / c_4_4_attestation_uri, or `saf attest apply`.]"
    end
  else
    doc = document_attestation(uri, max_age_days: input('attestation_max_age_days', value: 365))
    describe "Boundary policy attestation (C-4.4) (#{uri})" do
      it('reachable') { expect(doc.connection_error).to be_nil, "attestation unreachable: #{doc.connection_error}" }
      it('exists') { expect(doc.exists?).to eq(true) }
      it("current") { expect(doc.current?).to eq(true) }
    end
  end
end
