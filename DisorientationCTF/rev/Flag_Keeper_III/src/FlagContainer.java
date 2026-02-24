package com.cisa.ctf;

import java.io.Serializable;

public class FlagContainer implements Serializable {
   private static final long serialVersionUID = 1L;
   private final boolean d;
   private final String bab;
   private final char[] ft;
   private final String aba;
   private final char[] a;
   private final int le;

   public FlagContainer(char[] a, char[] ft, int le, boolean d, String bab, String aba) {
      this.a = a;
      this.ft = ft;
      this.le = le;
      this.d = d;
      this.bab = bab;
      this.aba = aba;
   }

   public String toString() {
      StringBuilder sb = new StringBuilder("disorientation");
      sb.append("{");

      for(int i = 0; i < this.ft.length; ++i) {
         sb.append(this.ft[i]);
      }

      sb.append("}");
      return sb.toString();
   }
}
