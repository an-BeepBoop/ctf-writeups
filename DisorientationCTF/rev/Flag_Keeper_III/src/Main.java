package com.cisa.ctf;

public class Main {
   public static void main(String[] args) throws Exception {
      Server.getInstance().run(new FK3Auth());
   }
}
