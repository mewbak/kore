/*
*/

module VERIFICATION
  imports BMC

endmodule


module TEST2-SPEC
  imports VERIFICATION
  imports BMC

  rule (<T> <k> #execute </k> <state> "x" |-> X </state> </T>) #Implies (#AG(#Forall Y . #Forall _ .((<T> <k> #execute </k> <state> "x" |-> Y </state> </T>) #Implies {X ==Int Y #Equals true})))  [kore]

endmodule
