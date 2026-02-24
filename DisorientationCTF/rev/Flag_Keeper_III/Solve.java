import java.io.*;

public class Solve {
  public static void main(String[] args) throws Exception {
    ObjectInputStream ois = new ObjectInputStream(new FileInputStream("flag.bin"));
    // Needs the FlagContainer.class present
    Object obj = ois.readObject();
    System.out.println(obj);
  }
}
