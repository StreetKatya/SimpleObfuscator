package ru.streetkatya;

public class Test2 {
    public Test2() {}
    public static String test = "KB";
    public static String SumTest(String a, String b) {
        System.out.println(a+ "! ");
        System.out.println(b+ "! ");
        return a+b;
    }
    public static void main(String[] args) {
        System.out.println(SumTest("I", "Love") + test);
    }
}
