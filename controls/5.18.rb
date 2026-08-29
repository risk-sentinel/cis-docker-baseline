# encoding: UTF-8

control 'C-5.18' do
  title 'Ensure that host devices are not directly exposed to containers'
  desc  "
    Host devices can be directly exposed to containers at runtime. Do not directly expose host devices to containers, especially to containers that are not trusted.

    The `--device` option exposes host devices to containers and as a result of this, containers can directly access these devices. The the container would not need to run in `privileged` mode to access and manipulate them, as by default, the container is granted this type of access. Additionally, it would possible for containers to remove block devices from the host. You therefore should not expose host devices to containers directly.

    If for some reason you wish to expose the host device to a container you should consider which sharing permissions you wish to use on a case by case base as appropriate to your organization:

    - r - read only
    - w - writable
    - m - mknod allowed
  "
  desc  'rationale', "
    Host devices can be directly exposed to containers at runtime. Do not directly expose host devices to containers, especially to containers that are not trusted.

    The `--device` option exposes host devices to containers and as a result of this, containers can directly access these devices. The the container would not need to run in `privileged` mode to access and manipulate them, as by default, the container is granted this type of access. Additionally, it would possible for containers to remove block devices from the host. You therefore should not expose host devices to containers directly.

    If for some reason you wish to expose the host device to a container you should consider which sharing permissions you wish to use on a case by case base as appropriate to your organization:

    - r - read only
    - w - writable
    - m - mknod allowed
  "
  desc  'check', "
    You should use the command below:
    ```
    docker ps --quiet --all | xargs docker inspect --format '{{ .Id }}: Devices={{ .HostConfig.Devices }}'
    ```
    The above command would list out each device with below information:

    - `CgroupPermissions` - For example, `rwm`
    - `PathInContainer` - Device path within the container
    - `PathOnHost` - Device path on the host

    You should verify that the host device is needed to be accessed from within the container and that the permissions required are correctly set. If the above command returns [], then the container does not have access to host devices and is configured in line with good security practice.
  "
  desc  'fix', "
    You should not directly expose host devices to containers. If you do need to expose host devices to containers, you should use granular permissions as appropriate to your organization:

    For example, do not start a container using the command below:
    ```
    docker run --interactive --tty --device=/dev/tty0:/dev/tty0:rwm --device=/dev/temp_sda:/dev/temp_sda:rwm centos bash
    ```

    You should only share the host device using appropriate permissions:
    ```
    docker run --interactive --tty --device=/dev/tty0:/dev/tty0:rw --device=/dev/temp_sda:/dev/temp_sda:r centos bash
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-2 c']
  tag cci:                   ['CCI-002113']
  tag cis_number:            '5.18'
  tag cis_rid:               '5.18'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-0518r1_rule'
  tag cis_version:           '1.8.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'
  tag exec_validated:        false

  # Default Docker container /dev contents — anything else suggests
  # `--device` exposure of a host device.
  expected = %w[null zero full random urandom tty console ptmx pts mqueue shm stderr stdin stdout fd core]
  dev_listing = command('ls /dev').stdout.to_s.split.reject(&:empty?)
  unexpected = dev_listing - expected
  describe 'container /dev — unexpected device nodes (host devices possibly exposed)' do
    subject { unexpected }
    it { should be_empty }
  end
end
