# xfrm-policy-notifier
A small program that helps you monitor Linux XFRM policy changes.
Only XFRM updates are monitored since IPSec daemon I use generates updates for link creations.

## Howto
Packages required: `libnl-3-dev libnl-xfrm-3-dev`

Build project: `mkdir build && cd build && cmake .. && make`

## Usage
Sample Ruby script:
```ruby
require 'pty'

begin
PTY.spawn("./xfrm_policy_notifier") do |stdout, stdin, pid|
    begin
    stdout.each do |line|
        # do something on updates
    end
    rescue Errno::EIO
    end
end
rescue PTY::ChildExited
end
```