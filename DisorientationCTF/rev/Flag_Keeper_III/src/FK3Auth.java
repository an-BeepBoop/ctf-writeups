package com.cisa.ctf;

public class FK3Auth implements AbstractAuthenticator {
   public boolean auth(AuthItem authItem) {
      return Registry.admin2.equals(authItem);
   }
}
