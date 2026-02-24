package com.cisa.ctf;

import java.util.Scanner;

public class Server {
   private static Server SINGLETON = null;

   private Server() {
   }

   public void displayFlag() {
      System.out.println("This method is still under construction!");
   }

   public void run(AbstractAuthenticator abstractAuthenticator) throws Exception {
      System.out.println("Welcome to Flag Keeper v3, sorry about our previous breaches, hopefully this version is more secure.");
      Scanner scanner = new Scanner(System.in);

      while(true) {
         while(true) {
            System.out.println("Enter your username.");
            String username = scanner.nextLine();
            System.out.println("Enter your password.");
            String password = scanner.nextLine();
            if (abstractAuthenticator.auth(username, password)) {
               System.out.println("Authentication success.");
               if (SecurityCheck.check()) {
                  this.displayFlag();
               } else {
                  System.out.println("Security check failed!");
               }
            } else {
               System.out.println("Authentication failed.");
            }
         }
      }
   }

   public static Server getInstance() {
      if (SINGLETON == null) {
         SINGLETON = new Server();
      }

      return SINGLETON;
   }
}
