package com.cisa.ctf;

public interface AbstractAuthenticator {
   default boolean auth(String username, String password) {
      return this.auth(new AuthItem(username, password));
   }

   boolean auth(AuthItem var1);
}
