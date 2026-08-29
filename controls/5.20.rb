# encoding: UTF-8

control 'C-5.20' do
  title 'Ensure mount propagation mode is not set to shared'
  desc  "
    Mount propagation mode allows mounting volumes in shared, slave or private mode on a container. Do not use shared mount propagation mode unless explicitly needed.

    A shared mount is replicated at all mounts and changes made at any mount point are propagated to all other mount points. 

    Mounting a volume in shared mode does not restrict any other container from mounting and making changes to that volume. 

    As this is likely not a desirable option from a security standpoint, this feature should not be used unless explicitly required.
  "
  desc  'rationale', "
    Mount propagation mode allows mounting volumes in shared, slave or private mode on a container. Do not use shared mount propagation mode unless explicitly needed.

    A shared mount is replicated at all mounts and changes made at any mount point are propagated to all other mount points. 

    Mounting a volume in shared mode does not restrict any other container from mounting and making changes to that volume. 

    As this is likely not a desirable option from a security standpoint, this feature should not be used unless explicitly required.
  "
  desc  'check', "
    ```
    docker ps --quiet --all | xargs docker inspect --format '{{ .Id }}: Propagation={{range $mnt := .Mounts}} {{json $mnt.Propagation}} {{end}}'
    ```

    The above command returns the propagation mode for mounted volumes. The propagation mode should not be set to `shared` unless needed. The above command might throw errors if there are no mounts. In that case, this recommendation is not applicable.
  "
  desc  'fix', "
    Do not mount volumes in shared mode propagation.

    For example, do not start a container as below:

    ```
    docker run --volume=/hostPath:/containerPath:shared ```
  "
  impact 0.5
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['CM-6 b']
  tag ksi:                   ['KSI-CMT-LMC', 'KSI-CMT-RMV', 'KSI-MLA-EVC', 'KSI-SVC-ACM']
  tag nist_r4:               ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_number:            '5.20'
  tag cis_rid:               '5.20'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-0520r1_rule'
  tag cis_version:           '1.8.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'
  tag exec_validated:        false

  # /proc/self/mountinfo has fields: mount-id, parent-id, major:minor,
  # root, mount-point, options, optional-fields, ... where optional-
  # fields can include `shared:N` / `master:N`. CIS wants no `shared:`
  # on container mounts.
  shared_mounts = file('/proc/self/mountinfo').content.to_s.lines.select { |l| l =~ /\sshared:\d/ }
  describe 'container mount points with shared propagation' do
    subject { shared_mounts.map(&:strip) }
    it { should be_empty }
  end
end
