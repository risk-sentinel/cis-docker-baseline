# encoding: UTF-8

control 'C-5.13' do
  title 'Ensure that the container\'s root filesystem is mounted as read only'
  desc  "
    The container's root filesystem should be treated as a 'golden image' by using Docker run's `--read-only` option. This prevents any writes to the container's root filesystem at container runtime and enforces the principle of immutable infrastructure.

    Enabling this option forces containers at runtime to explicitly define their data writing strategy to persist or not persist their data.

    This also reduces security attack vectors since the container instance's filesystem cannot be tampered with or written to unless it has explicit read-write permissions on its filesystem folder and directories.
  "
  desc  'rationale', "
    The container's root filesystem should be treated as a 'golden image' by using Docker run's `--read-only` option. This prevents any writes to the container's root filesystem at container runtime and enforces the principle of immutable infrastructure.

    Enabling this option forces containers at runtime to explicitly define their data writing strategy to persist or not persist their data.

    This also reduces security attack vectors since the container instance's filesystem cannot be tampered with or written to unless it has explicit read-write permissions on its filesystem folder and directories.
  "
  desc  'check', "
    You should run the following command on the docker host:

    ```
    docker ps --quiet --all | xargs docker inspect --format '{{ .Id }}: ReadonlyRootfs={{ .HostConfig.ReadonlyRootfs }}' 
    ```

    If the above command returns `true`, it means the container's root filesystem is mounted read-only. 

    If the above command returns `false`, it means the container's root filesystem is writeable.
  "
  desc  'fix', "
    You should add a `--read-only` flag at a container's runtime to enforce the container's root filesystem being mounted as read only. 

    ```
    docker run --read-only ```

    Enabling the `--read-only` option at a container's runtime should be used by administrators to force a container's executable processes to only write container data to explicit storage locations during its lifetime.

    Examples of explicit storage locations during a container's runtime include, but are not limited to:  
  
    1. Using the `--tmpfs` option to mount a temporary file system for non-persistent data writes. 

    ```
    docker run --interactive --tty --read-only --tmpfs \"/run\" --tmpfs \"/tmp\" centos /bin/bash
    ```   

    2. Enabling Docker `rw` mounts at a container's runtime to persist container data directly on the Docker host filesystem.  

    ```
    docker run --interactive --tty --read-only -v /opt/app/data:/run/app/data:rw centos /bin/bash
    ```  

    3. Utilizing the Docker shared-storage volume plugin for Docker data volume to persist container data.  

    ```
    docker volume create -d convoy --opt o=size=20GB my-named-volume
    ```

    ```
    docker run --interactive --tty --read-only -v my-named-volume:/run/app/data centos /bin/bash
    ```

    3. Transmitting container data outside of the Docker controlled area during the container's runtime for container data in order to ensure that it is persistent.  Examples include hosted databases, network file shares and APIs.
  "
  impact 0.5
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-2 c', 'AC-8 a']
  tag cci:                   ['CCI-002113', 'CCI-000051']
  tag cis_number:            '5.13'
  tag cis_rid:               '5.13'
  tag cis_benchmark:         'CIS Docker Benchmark v1.8.0'
  tag cis_rule_id:           'SV-0513r1_rule'
  tag cis_version:           '1.8.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'
  tag exec_validated:        false

  # /proc/mounts line for "/" ends with "ro" if the root fs is read-only.
  root_mount = file('/proc/mounts').content.to_s.lines.find { |l| l.split[1] == '/' }
  describe "container root filesystem mount options (#{root_mount.to_s.strip})" do
    subject { root_mount.to_s.split(' ', 4)[3].to_s.split(',').first }
    it { should eq 'ro' }
  end
end
