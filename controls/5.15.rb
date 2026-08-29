# encoding: UTF-8

control 'C-5.15' do
  title 'Ensure that the \'on-failure\' container restart policy is set to \'5\''
  desc  "
    By using the `--restart` flag in the `docker run` command you can specify a restart policy for how a container should or should not be restarted on exit. You should choose the `on-failure` restart policy and limit the restart attempts to `5`.

    If you indefinitely keep trying to start the container, it could possibly lead to a denial of service on the host. It could be an easy way to do a distributed denial of service attack especially if you have many containers on the same host. Additionally, ignoring the exit status of the container and always attempting to restart the container, leads to non-investigation of the root cause behind containers getting terminated. If a container gets terminated, you should investigate on the reason behind it instead of just attempting to restart it indefinitely.  You should use the `on-failure` restart policy to limit the number of container restarts to a maximum of `5` attempts.
  "
  desc  'rationale', "
    By using the `--restart` flag in the `docker run` command you can specify a restart policy for how a container should or should not be restarted on exit. You should choose the `on-failure` restart policy and limit the restart attempts to `5`.

    If you indefinitely keep trying to start the container, it could possibly lead to a denial of service on the host. It could be an easy way to do a distributed denial of service attack especially if you have many containers on the same host. Additionally, ignoring the exit status of the container and always attempting to restart the container, leads to non-investigation of the root cause behind containers getting terminated. If a container gets terminated, you should investigate on the reason behind it instead of just attempting to restart it indefinitely.  You should use the `on-failure` restart policy to limit the number of container restarts to a maximum of `5` attempts.
  "
  desc  'check', "
    You should use the command below
    ```
    docker ps --quiet --all | xargs docker inspect --format '{{ .Id }}: RestartPolicyName={{ .HostConfig.RestartPolicy.Name }} MaximumRetryCount={{ .HostConfig.RestartPolicy.MaximumRetryCount }}'
    ```

    If this command returns `RestartPolicyName=always`, then the system is not configured optimally.
    If the above command returns `RestartPolicyName=no` or just `RestartPolicyName=`, then restart policies are not being used and the container would never be restarted automatically.  Whilst this may be a secure option, it is not the best option from a usability standpoint.
    If the above command returns `RestartPolicyName=on-failure`, then verify that the number of restart attempts is set to `5` or less by looking at `MaximumRetryCount`.
  "
  desc  'fix', "
    If you wish a container to be automatically restarted, a sample command is as below:
    ```
    docker run --detach --restart=on-failure:5 nginx
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['IA-5 (1) (e)']
  tag nist_r4:               ['IA-5 (1) (e)']
  tag cci:                   ['CCI-000200']
  tag cis_number:            '5.15'
  tag cis_rid:               '5.15'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-0515r1_rule'
  tag cis_version:           '1.8.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'alternative'
  tag attestation_category:  'policy'
  tag exec_validated:        false

  uri = input('c_5_15_attestation_uri', value: '')
  uri = attestation_uri(:boundary, 'C-5.15') if uri.to_s.empty?
  if uri.to_s.empty?
    describe 'Requires manual review and attestation' do
      skip "Requires manual review and attestation provided for this control (on-failure restart policy is set on ECS service / task definition (not on the container itself); operators cross-reference the task-definition restart-policy field) [Lift: set boundary_docs_base / c_5_15_attestation_uri, or `saf attest apply`.]"
    end
  else
    doc = document_attestation(uri, max_age_days: input('attestation_max_age_days', value: 365))
    describe "Boundary policy attestation (C-5.15) (#{uri})" do
      it('reachable') { expect(doc.connection_error).to be_nil, "attestation unreachable: #{doc.connection_error}" }
      it('exists') { expect(doc.exists?).to eq(true) }
      it("current") { expect(doc.current?).to eq(true) }
    end
  end
end
