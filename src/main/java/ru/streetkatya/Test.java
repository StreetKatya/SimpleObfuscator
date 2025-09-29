package ru.streetkatya;

public class Test {
    // Поле класса с семантически значимым именем
    private String secretMessage = "Это секретное сообщение";

    // Метод с семантически значимым именем
    public void printSecret() {
        // Локальная переменная и строковый литерал
        String greeting = "Привет, мир!";
        System.out.println(greeting);
        System.out.println(this.secretMessage);
    }

    public static void main(String[] args) {
        Test test = new Test();
        test.printSecret();
    }
}
