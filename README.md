# Network Routing Simulation

<img src="https://storage.googleapis.com/starfighter-public-bucket/wiki_images/resume_photos/RUSHBSwitch/pictures/pic9.PNG"
    width="700px">

## What is this?

A project about routing packets through a network. Given 
    [this specification](https://storage.googleapis.com/starfighter-public-bucket/wiki_images/resume_photos/RUSHBSwitch/spec.pdf),
    I was tasked with implementing part C in either python, java, or c/c++.

### Simulation environment
---

The simulation we created was to be run on the universities on site linux 
    environment (called MOSS) which we could connect to via `ssh`.

### Network switch modes
---

The task was to create a script called `RUSHBSwitch.py` which could operate
    in one of three modes:

- Local: The switch bound a UDP listening socket to a port number on a
    localhost address, allowing processes running `RUSHBAdapter.py` to 
    communicate with it.

- Global: The switch bound a TCP greeter socket to a port number on a localhost
    address, allowing other processes `RUSHBSwitch.py` to connect and 
    communicate with it.

- Hybrid: The switch bound BOTH a UDP, and TCP socket.

Both local and global mode had a `stdin` input for instructing the 
    process running `RUSHBSwitch.py` to connect to other switches (allowing for
    us to set up a network like the one seen below).

<img src="https://storage.googleapis.com/starfighter-public-bucket/wiki_images/resume_photos/RUSHBSwitch/pictures/pic1.PNG"
    width="700px">

Hybrid switches did not have an input terminal.

### Network switch addressing scheme
---

Each switch maintains its own subnet, and allocates IP addresses to other 
    switches via a DHCP-like protocol (which this assignment refers to as a 
    '*greeting*'). Each allocated IP-address is associated with a port number.

If the switch already has some existing connections, and happens to have just
    received a `location packet`, then the switch will forward said packet
    to its neighbours. This aim here is to implement an algorithm somewhat
    similar to a **DV algorithm** as to allow each router to figure out
    the shortest route to each other router in the network (wow what a mouthful 
    of the word 'route').

<img src="https://storage.googleapis.com/starfighter-public-bucket/wiki_images/resume_photos/RUSHBSwitch/pictures/pic3.PNG"
    width="700px">

### Packet fragmentation and state info tracking
---

The implementation also had to support **packet fragmentation** keep track of 
    state information at each router (i.e. each router had to ask the next
    router on its list whether it was ready to receive or not). 

If the intended destination was a switch (and not another adapter), then the 
    switch was supposed to buffer the fragments, and reassemble the message 
    when all fragments were eventually received.

### Network link cost
---
Cost for each link was determined via a simple euclidean norm calculation 
    between the two routers.

<img src="https://storage.googleapis.com/starfighter-public-bucket/wiki_images/resume_photos/RUSHBSwitch/pictures/pic2.PNG"
    width="350px">

## How do I use this thing ?

### Normal mode
---
To see how the software works, do the following:

1. Clone the repo and, with your favourite terminal, `cd` into the root 
    directory (the place where `RUSHBSwitch.py` is).

2. In this terminal, you may run the switch in whatever mode you want:

```
python3 RUSHBSwitch.py {local|global} {ip} [optional_ip] {x} {y}
```

for example, if I wanted to run the switch in local mode with the switch at 
    point (0,0), I'd type:

```
python3 RUSHBSwitch.py local 10.10.10.10/24 0 0 
```

Hitting enter, you should see the following output

```
12345
> 
```

The first number is the port number of your listening port (in this case, it's 
    a UDP port).

The second character is the *terminal indicator*, like what you have for a 
    regular terminal.

3. In order to connect to the switch and begin communicating with it, 
    in another terminal run, the following command:

```
python3 RUSHBAdapter.py 12345
```

This will perform the DHCP-like connection protocol. Once finished, you
    should see the following:

```
> 
```

From here, you may send some data to the switch using the following command

```
send {receiver_ip_address} "{message}"
```

for example `(on the RUSHBAdapter.py side)`

```
send 10.10.10.10 "Hello there"
```

Which will provide the following output on the `RUSHBSwitch.py` side:

```
Received from 10.10.10.11: Hello there
```

### Local Switch Example conversation
---

If you want to communicate with another adapter, you can spawn a third terminal 
    and connect another `RUSHBAdapter.py` process to the same switch. 
    Then following the same proceedure as outlined above, you can send messages 
    between the adapters:

<img src="https://storage.googleapis.com/starfighter-public-bucket/wiki_images/resume_photos/RUSHBSwitch/pictures/pic4.PNG"
    width="350px">

For example (follow these actions sequentially)

```
// Terminal 1

python3 RUSHBSwitch.py local 10.10.10.10/24 0 0 
12345 
>
```

```
// Terminal 2

python3 RUSHBAdapter.py 12345
>

// Gets assigned 10.10.10.11
```

```
// Terminal 3

python3 RUSHBAdapter.py 12345
>

// Gets assigned 10.10.10.12
```

```
// Terminal 2

> send 10.10.10.12 "Hello there"
```

```
// Terminal 3

Received from 10.10.10.11: Hello there
> send 10.10.10.11 "General Kenobi!"
```

```
// Terminal 2

Received from 10.10.10.12: General Kenobi!
>
```

### Switch connection example
---
A switch in either global or local mode can connect to another switch through
the following command

```
> connect {port_number}
```

An example of three switches connecting to each other is shown below 
    (follow these actions sequentially).

```
// Terminal 1 (Local switch)

python3 RUSHBSwitch.py local 10.10.10.10/24 0 0
4444
>
```

```
// Terminal 2 (Global switch)

python3 RUSHBSwitch.py global 20.20.20.20/24 10 10
5555
>
```

```
// Terminal 3 (Global switch)

python3 RUSHBSwitch.py global 30.30.30.30/24 10 10
6666
>
```

```
// Terminal 1 (Local switch)

> connect 5555

// Gets assigned 20.20.20.21
```

```
// Terminal 2 (Global switch)

> connect 6666

// Gets assigned 30.30.30.31
```

Now we should have something that looks like this:

<img src="https://storage.googleapis.com/starfighter-public-bucket/wiki_images/resume_photos/RUSHBSwitch/pictures/pic5.PNG"
    width="700px">

Now (without complicating things further) we can send a message from T1 to T3
like so:

```
// Terminal 1

send 30.30.30.30 "G'day mate"
```

```
// Terminal 3

Received from 20.20.20.21: G'day mate
```

Which graphically looks like so:

<img src="https://storage.googleapis.com/starfighter-public-bucket/wiki_images/resume_photos/RUSHBSwitch/pictures/pic6.PNG"
    width="700px">

Now you might be wondering

> How did T1 know to send the packet to T2? It was never told that T3 existed.

That's true, however, we mentioned previously that if T2 had existing 
    neightbours, then when it received a distance packet, it would forward that
    distance packet to said neighbours.

Graphically this looks like so:

<img src="https://storage.googleapis.com/starfighter-public-bucket/wiki_images/resume_photos/RUSHBSwitch/pictures/pic7.PNG"
    width="700px">

Hence T1 knows that it can get to T3 via T2.

If you want to see how this works in more detail, see the **Debug mode** 
    section.

In the event that the T1 does not know where to send the packet, it will 
    default to **longest prefix matching** of the next switch IP address.

### Testing mode
---
A number of tests were provided to confirm some of our functionality.

NOTE, these tests were shown to be functional on the universities MOSS 
    environment. As such, I don't believe they're functional on Windows 
    machines.

To run these tests, do the following:

1. `cd` into the `RUSHBNetwork` directory

2. Run the following command

```
python3 RUSHB.py [-m mode] [-o output]
```

with any of the following modes

- `SWITCH_GREETING_ADAPTER`
- `SWITCH_FORWARD_MESSAGE`
- `SWITCH_DISTANCE_SWITCH`
- `SWITCH_ROUTING_SIMPLE`
- `SWITCH_ROUTING_PREFIX`
- `SWITCH_GLOBAL_GREETING`
- `MINIMAP_3`
- `SWITCH_LOCAL2_GREETING`
- `SWITCH_MULTI_ADAPTER`

e.g.

```
python3 RUSHB.py -m SWITCH_GREETING_ADAPTER -o SWITCH_GREETING_ADAPTER.bout_2
```

The script will instruct you what to do from there, the key thing to realise
    is the `RUSHB.py` script will act as a stand in for the various elements
    the `RUSHBSwitch.py` is supposed to communicate with.

Hence you'll only need two terminals for testing.

You can check if the output you get from the test is correct by using `vimdiff`
    against `your_output_file.bout_2` and `test_files/test_name.bout`

### Debug mode
---

In the `RUSHBHelper.py` file, there is a variable which looks like this:

```
__DEBUG_MODE_ENABLED__ = False
```

Setting this to `True` will allow for debug printouts (and generally a 
    better understanding of what the heck is going on).

For example, here are two terminal printouts side by side:

<img src="https://storage.googleapis.com/starfighter-public-bucket/wiki_images/resume_photos/RUSHBSwitch/pictures/test1.PNG"
    width="700px">

We can see clearly that this is indeed a greeting by the green 
    **GREETING PACKET CONTENTS** header.

More intuitively, we can see how it mimics the discover, offer, request, and
    acknowledge flow diagram above.

<img src="https://storage.googleapis.com/starfighter-public-bucket/wiki_images/resume_photos/RUSHBSwitch/pictures/test2.PNG"
    width="700px">

For all aspects of the simulation, there are plenty of debug printouts 
    spread throughout, so you should have no trouble getting a grasp of what 
    threads are being passed what messages and when.

If I were to do this again however, I'd introduce timestamps as to allow for
    debug prinout timeline construction (a nice thing to have in when network
    complexity increases).