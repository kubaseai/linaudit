# linaudit
Auditd replacement for multi-core Amazon EC2 instances

Have you ever used some EDR (Endpoint Detection & Response) solution on a machine with 96 CPUs?
There is high probability that single-threaded audit netlink receiver is not able to process in time received events.
Receiver should pass the event to multi-threaded processor. This is the design concept standing behind linAUDIT.
