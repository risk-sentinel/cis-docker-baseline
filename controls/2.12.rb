# encoding: UTF-8

control 'C-2.12' do
  title 'Ensure base device size is not changed until needed'
  desc  "
    Under certain circumstances, you might need containers larger than 10G. Where this applies you should carefully choose the base device size.

    The base device size can be increased on daemon restart. Increasing the base device size allows all future images and containers to be of the new base device size. A user can use this option to expand the base device size, however shrinking is not permitted. This value affects the system wide \"base\" empty filesystem that may already be initialized and therefore inherited by pulled images.

    Although the file system does not allocate the increased size as long as it is empty, more space will be allocated for extra images. This may cause a denial of service condition if the allocated partition becomes full.
  "
  desc  'rationale', "
    Under certain circumstances, you might need containers larger than 10G. Where this applies you should carefully choose the base device size.

    The base device size can be increased on daemon restart. Increasing the base device size allows all future images and containers to be of the new base device size. A user can use this option to expand the base device size, however shrinking is not permitted. This value affects the system wide \"base\" empty filesystem that may already be initialized and therefore inherited by pulled images.

    Although the file system does not allocate the increased size as long as it is empty, more space will be allocated for extra images. This may cause a denial of service condition if the allocated partition becomes full.
  "
  desc  'check', "
    To confirm this setting the dockerd start-up options and any settings in `/etc/docker/daemon.json` should be reviewed.

    To review the dockerd startup options, use:
    ```
    grep \"--storage-opt dm.basesize\" /etc/docker/daemon.json
    ```
    Execute the above command and it should not show any `--storage-opt dm.basesize` parameters.

    The contents of `/etc/docker/daemon.json` should also be reviewed
  "
  desc  'fix', "
    Do not set `--storage-opt dm.basesize` until needed.
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['CM-6 a']
  tag cci:                   ['CCI-000363']
  tag cis_number:            '2.12'
  tag cis_rid:               '2.12'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-0212r1_rule'
  tag cis_version:           '1.8.0'
  tag cis_level:             1
  tag cis_scored:            true
  if input('docker_target_mode') == 'container_only'
    tag implementation_status:  'inherited'
    tag inherited_from:         'aws-shared-responsibility'
    tag attestation_references: ['AWS SOC 2 Type II', 'AWS FedRAMP Moderate', 'AWS FedRAMP High', 'AWS ISO 27001']
  else
    tag implementation_status:  'alternative'
  end
  tag exec_validated:           false

  if input('docker_target_mode') == 'container_only'
    uri = input('inherited_evidence_uri', value: '')
    uri = attestation_uri(:leveraged, 'aws-soc2-type2', ext: 'json') if uri.to_s.empty?
    if uri.to_s.empty?
      describe 'AWS shared-responsibility evidence (no leveraged source configured)' do
        skip 'inherited-from-aws: set leveraged_evidence_base / inherited_evidence_uri to the pulled AWS evidence manifest (SOC 2 / FedRAMP / ISO), or `saf attest apply`.'
      end
    else
      doc = document_attestation(uri, max_age_days: input('leveraged_evidence_max_age_days', value: 365))
      describe "AWS shared-responsibility leveraged evidence (#{uri})" do
        it('reachable') { expect(doc.connection_error).to be_nil, "evidence unreachable: #{doc.connection_error}" }
        it('exists') { expect(doc.exists?).to eq(true) }
        it("current") { expect(doc.current?).to eq(true) }
      end
    end
  else
    describe 'Requires manual review and attestation' do
      skip "Requires manual review and attestation provided for this control (historical devicemapper-only concern; consumers using overlay2 or other modern drivers attest non-applicability)"
    end
  end
end
