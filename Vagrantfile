Vagrant.configure("2") do |config|
  config.vm.box="ubuntu-22.04-vulnerable"
  config.vm.box_url = "https://cloud-images.ubuntu.com/releases/22.04/release-20230107/ubuntu-22.04-server-cloudimg-amd64-vagrant.box"
  config.vm.box_download_checksum = "f37c8dbda2d712ffb6242b7b9d88058298caf3a860ae29620de1cd4d02b59a9a"
  config.vm.box_download_checksum_type = "sha256"

  config.vm.provision "shell", path: "provision.sh", reboot: true
end
