package com.cisa.ctf;

public record AuthItem(String username, String password) {
   public AuthItem(String username, String password) {
      this.username = username;
      this.password = password;
   }

   public boolean equals(Object obj) {
      if (!(obj instanceof AuthItem)) {
         return false;
      } else {
         AuthItem authItem = (AuthItem)obj;
         return authItem.username.equals(this.username) && authItem.password.equals(this.password);
      }
   }

   public String username() {
      return this.username;
   }

   public String password() {
      return this.password;
   }
}
