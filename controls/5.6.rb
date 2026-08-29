# encoding: UTF-8

control 'C-5.6' do
  title 'Ensure sensitive host system directories are not mounted on containers'
  desc  "
    You should not allow sensitive host system directories such as those listed below to be mounted as container volumes, especially in read-write mode.  

    ```
    /
    /boot
    /dev
    /etc
    /lib
    /lib64
    /proc
    /sys
    /usr
    ```

    If sensitive directories are mounted in read-write mode, it could be possible to make changes to files within them. This has obvious security implications and should be avoided.
  "
  desc  'rationale', "
    You should not allow sensitive host system directories such as those listed below to be mounted as container volumes, especially in read-write mode.  

    ```
    /
    /boot
    /dev
    /etc
    /lib
    /lib64
    /proc
    /sys
    /usr
    ```

    If sensitive directories are mounted in read-write mode, it could be possible to make changes to files within them. This has obvious security implications and should be avoided.
  "
  desc  'check', "
    You should run the following command:
    ```
    docker ps --quiet --all | xargs docker inspect --format '{{ .Id }}: Volumes={{ .Mounts }}'
    ```
    This command returns a list of currently mapped directories and indicates whether they are mounted in read-write mode for each container instance.
  "
  desc  'fix', "
    You should not mount directories which are security sensitive on the host within containers, especially in read-write mode.
  "
  impact 0.5
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['CM-6 b']
  tag nist_r4:               ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_number:            '5.6'
  tag cis_rid:               '5.6'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-0506r1_rule'
  tag cis_version:           '1.8.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'alternative'
  tag attestation_category:  'policy'
  tag exec_validated:        false

  uri = input('c_5_6_attestation_uri', value: '')
  uri = attestation_uri(:boundary, 'C-5.6') if uri.to_s.empty?
  if uri.to_s.empty?
    describe 'Requires manual review and attestation' do
      skip "Requires manual review and attestation provided for this control (\"sensitive host directories\" depends on the host filesystem layout the consumer manages; the in-container scan context has no view of the host. Operator attests from their volume-mount inventory (`docker inspect` output on host_daemon scans, or the orchestrator's task / pod spec for managed runtimes). Auto-detection in container_only mode is not feasible.) [Lift: set boundary_docs_base / c_5_6_attestation_uri, or `saf attest apply`.]"
    end
  else
    doc = document_attestation(uri, max_age_days: input('attestation_max_age_days', value: 365))
    describe "Boundary policy attestation (C-5.6) (#{uri})" do
      it('reachable') { expect(doc.connection_error).to be_nil, "attestation unreachable: #{doc.connection_error}" }
      it('exists') { expect(doc.exists?).to eq(true) }
      it("current") { expect(doc.current?).to eq(true) }
    end
  end
end
