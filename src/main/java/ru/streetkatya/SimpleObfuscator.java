package ru.streetkatya;

import org.objectweb.asm.*;
import org.objectweb.asm.commons.ClassRemapper;
import org.objectweb.asm.commons.Remapper;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

/**
 * Комплексный демонстрационный обфускатор, реализующий многоэтапную стратегию
 * защиты Java байт-кода с использованием библиотеки ASM.
 */
public class SimpleObfuscator {

    // --- НАСТРОЙКИ ---
    /**
     * ВАЖНО: Укажите здесь имя вашего пакета в формате для байт-кода (с '/' вместо '.').
     * Обфускатор будет изменять только классы внутри этого пакета.
     */
    private static final String PACKAGE_TO_OBFUSCATE = "ru/streetkatya/";

    /**
     * Имя для метода-дешифратора до его финального переименования.
     */
    private static final String DECRYPT_METHOD_NAME = "decrypt";

    // --- Внутренние утилиты ---
    private static final Map<String, String> remappingLog = new HashMap<>();
    private static final Random random = new Random();

    /**
     * Главный метод, запускающий процесс обфускации.
     * @param args Аргументы командной строки (не используются).
     * @throws IOException Если возникает ошибка чтения или записи файла.
     */
    public static void main(String[] args) throws IOException {
        String FileName = "Test";
        // ВАЖНО: Укажите правильный путь к .class файлу, который вы хотите обфусцировать.
        String inputClassFile = "build/classes/java/main/" + PACKAGE_TO_OBFUSCATE + FileName +".class";
        String outputClassFile = "output/"+ PACKAGE_TO_OBFUSCATE + FileName +".class";

        System.out.println("Начало обфускации файла: " + FileName+".java");

        // 1. Инициализация инструментов ASM
        FileInputStream is = new FileInputStream(inputClassFile);
        ClassReader classReader = new ClassReader(is);

        // Используем COMPUTE_FRAMES, чтобы ASM автоматически рассчитала
        // карты стека (Stack Map Frames). Это критически важно для совместимости
        // с Java 7+ и предотвращения ошибки VerifyError.
        ClassWriter classWriter = new ClassWriter(ClassWriter.COMPUTE_FRAMES);

        // 2. Настройка логики переименования полей и методов
        Remapper fieldAndMethodRenamer = new Remapper() {
            @Override
            public String mapMethodName(String owner, String name, String descriptor) {
                if (owner.startsWith(PACKAGE_TO_OBFUSCATE) && !name.equals("<init>") && !name.equals("main") && !name.equals("<clinit>")) {
                    String key = owner + "." + name + descriptor;
                    return remappingLog.computeIfAbsent(key, k -> "method_obf" + random.nextInt(1000));
                }
                return name;
            }

            @Override
            public String mapFieldName(String owner, String name, String descriptor) {
                if (owner.startsWith(PACKAGE_TO_OBFUSCATE)) {
                    String key = owner + "." + name;
                    return remappingLog.computeIfAbsent(key, k -> "field_obf" + random.nextInt(1000));
                }
                return name;
            }
        };

        // 3. Сборка конвейера посетителей (Visitor Chain)
        // Цепочка работает "изнутри наружу": ClassReader -> comprehensiveVisitor -> remappingVisitor -> classWriter
        ClassVisitor remappingVisitor = new ClassRemapper(classWriter, fieldAndMethodRenamer);
        ComprehensiveVisitor comprehensiveVisitor = new ComprehensiveVisitor(Opcodes.ASM9, remappingVisitor);

        // 4. Запуск процесса
        // Флаг EXPAND_FRAMES рекомендуется использовать при работе с COMPUTE_FRAMES.
        classReader.accept(comprehensiveVisitor, ClassReader.EXPAND_FRAMES);

        // 5. Запись результата
        FileOutputStream fos = new FileOutputStream(outputClassFile);
        fos.write(classWriter.toByteArray());
        fos.close();
        is.close();


        System.out.println("Обфускация успешно завершена. Результат в файле: " + outputClassFile);
        System.out.println("Карта переименований: " + remappingLog);
    }

    /**
     * Главный ClassVisitor, который управляет процессом внедрения дешифратора
     * и делегирует обработку методов своему кастомному MethodVisitor'у.
     */
    static class ComprehensiveVisitor extends ClassVisitor {
        private String className;
        private boolean isDecryptMethodPresent = false;

        public ComprehensiveVisitor(int api, ClassVisitor classVisitor) {
            super(api, classVisitor);
        }

        @Override
        public void visit(int version, int access, String name, String signature, String superName, String[] interfaces) {
            this.className = name;
            super.visit(version, access, name, signature, superName, interfaces);
        }

        @Override
        public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
            if (name.equals(DECRYPT_METHOD_NAME)) {
                isDecryptMethodPresent = true;
            }
            MethodVisitor methodVisitor = super.visitMethod(access, name, descriptor, signature, exceptions);
            // Для каждого метода создаем свой экземпляр посетителя, который будет шифровать строки
            // и переименовывать локальные переменные внутри этого метода.
            return new LocalVariableAndStringVisitor(api, methodVisitor, className);
        }

        @Override
        public void visitEnd() {
            // Если метод-дешифратор еще не был в классе, внедряем его.
            if (!isDecryptMethodPresent) {
                injectDecryptMethod();
            }
            super.visitEnd();
        }

        /**
         * Генерирует и внедряет байт-код статического метода-дешифратора.
         * Этот метод использует простой XOR-алгоритм для расшифровки строк.
         */
        private void injectDecryptMethod() {
            MethodVisitor mv = super.visitMethod(Opcodes.ACC_PUBLIC + Opcodes.ACC_STATIC,
                    DECRYPT_METHOD_NAME, "(Ljava/lang/String;)Ljava/lang/String;", null, null);
            mv.visitCode();
            mv.visitLdcInsn('K'); mv.visitVarInsn(Opcodes.ISTORE, 1);
            mv.visitTypeInsn(Opcodes.NEW, "java/lang/StringBuilder"); mv.visitInsn(Opcodes.DUP); mv.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/StringBuilder", "<init>", "()V", false); mv.visitVarInsn(Opcodes.ASTORE, 2);
            mv.visitInsn(Opcodes.ICONST_0); mv.visitVarInsn(Opcodes.ISTORE, 3);
            Label loopCondition = new Label(); mv.visitLabel(loopCondition);
            mv.visitVarInsn(Opcodes.ILOAD, 3); mv.visitVarInsn(Opcodes.ALOAD, 0); mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/String", "length", "()I", false);
            Label loopEnd = new Label(); mv.visitJumpInsn(Opcodes.IF_ICMPGE, loopEnd);
            mv.visitVarInsn(Opcodes.ALOAD, 2); mv.visitVarInsn(Opcodes.ALOAD, 0); mv.visitVarInsn(Opcodes.ILOAD, 3); mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/String", "charAt", "(I)C", false); mv.visitVarInsn(Opcodes.ILOAD, 1);
            mv.visitInsn(Opcodes.IXOR); mv.visitInsn(Opcodes.I2C); mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "append", "(C)Ljava/lang/StringBuilder;", false); mv.visitInsn(Opcodes.POP);
            mv.visitIincInsn(3, 1); mv.visitJumpInsn(Opcodes.GOTO, loopCondition);
            mv.visitLabel(loopEnd); mv.visitVarInsn(Opcodes.ALOAD, 2); mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "toString", "()Ljava/lang/String;", false);
            mv.visitInsn(Opcodes.ARETURN);
            mv.visitMaxs(0, 0); // Размеры будут пересчитаны автоматически благодаря COMPUTE_FRAMES
            mv.visitEnd();
        }
    }

    /**
     * Специализированный MethodVisitor, который выполняет две задачи:
     * 1. Находит и шифрует строковые константы.
     * 2. Находит и переименовывает локальные переменные.
     */
    static class LocalVariableAndStringVisitor extends MethodVisitor {
        private final String className;
        private final Map<String, String> localVariableMapping = new HashMap<>();

        public LocalVariableAndStringVisitor(int api, MethodVisitor methodVisitor, String className) {
            super(api, methodVisitor);
            this.className = className;
        }

        @Override
        public void visitLdcInsn(Object value) {
            if (value instanceof String) {
                String encryptedString = xorEncrypt((String) value);
                super.visitLdcInsn(encryptedString);
                super.visitMethodInsn(Opcodes.INVOKESTATIC, className, DECRYPT_METHOD_NAME, "(Ljava/lang/String;)Ljava/lang/String;", false);
            } else {
                super.visitLdcInsn(value);
            }
        }

        @Override
        public void visitLocalVariable(String name, String descriptor, String signature, Label start, Label end, int index) {
            if ("this".equals(name)) {
                super.visitLocalVariable(name, descriptor, signature, start, end, index);
                return;
            }
            String newName = localVariableMapping.computeIfAbsent(name, k -> generateRandomName());
            super.visitLocalVariable(newName, descriptor, signature, start, end, index);
        }

        private String generateRandomName() {
            String chars = "Il";
            int length = 15 + random.nextInt(6);
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < length; i++) {
                sb.append(chars.charAt(random.nextInt(chars.length())));
            }
            return sb.toString();
        }

        private String xorEncrypt(String input) {
            char key = 'K';
            StringBuilder output = new StringBuilder();
            for (int i = 0; i < input.length(); i++) {
                output.append((char) (input.charAt(i) ^ key));
            }
            return output.toString();
        }
    }
}