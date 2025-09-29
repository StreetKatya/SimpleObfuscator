package ru.streetkatya.obfuscator; // Создадим для библиотеки свой пакет

import org.objectweb.asm.*;
import org.objectweb.asm.commons.ClassRemapper;
import org.objectweb.asm.commons.Remapper;

import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

/**
 * Сервисный класс, предоставляющий ядро логики обфускации.
 * Предназначен для использования в качестве библиотеки.
 */
public class Obfuscator {

    private static final String DECRYPT_METHOD_NAME = "decrypt";
    private static final Random random = new Random();

    /**
     * Главный публичный метод. Принимает байт-код класса и имя пакета для обфускации,
     * возвращает обфусцированный байт-код.
     *
     * @param inputBytes         Массив байтов исходного .class файла.
     * @param packageToObfuscate Имя пакета для обфускации (например, "ru/streetkatya/").
     * @return Массив байтов обфусцированного .class файла.
     * @throws IOException Если возникает ошибка при чтении байтов.
     */
    public byte[] obfuscate(byte[] inputBytes, final String packageToObfuscate) throws IOException {
        ClassReader classReader = new ClassReader(inputBytes);
        ClassWriter classWriter = new ClassWriter(ClassWriter.COMPUTE_FRAMES);

        // Карта переименований создается для каждого вызова заново
        final Map<String, String> remappingLog = new HashMap<>();

        Remapper fieldAndMethodRenamer = new Remapper() {
            @Override
            public String mapMethodName(String owner, String name, String descriptor) {
                if (owner.startsWith(packageToObfuscate) && !name.equals("<init>") && !name.equals("<clinit>") && !name.equals("main")) {
                    String key = owner + "." + name + descriptor;
                    return remappingLog.computeIfAbsent(key, k -> "method_obf" + random.nextInt(1000));
                }
                return name;
            }

            @Override
            public String mapFieldName(String owner, String name, String descriptor) {
                if (owner.startsWith(packageToObfuscate)) {
                    String key = owner + "." + name;
                    return remappingLog.computeIfAbsent(key, k -> "field_obf" + random.nextInt(1000));
                }
                return name;
            }
        };

        ClassVisitor remappingVisitor = new ClassRemapper(classWriter, fieldAndMethodRenamer);
        ComprehensiveVisitor comprehensiveVisitor = new ComprehensiveVisitor(Opcodes.ASM9, remappingVisitor);

        classReader.accept(comprehensiveVisitor, ClassReader.EXPAND_FRAMES);

        return classWriter.toByteArray();
    }

    // --- Внутренние классы-посетители (остаются такими же, как и были) ---

    static class ComprehensiveVisitor extends ClassVisitor {
        private String className;
        private boolean isDecryptMethodPresent = false;

        public ComprehensiveVisitor(int api, ClassVisitor classVisitor) { super(api, classVisitor); }

        @Override
        public void visit(int version, int access, String name, String signature, String superName, String[] interfaces) {
            this.className = name;
            super.visit(version, access, name, signature, superName, interfaces);
        }

        @Override
        public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
            if (name.equals(DECRYPT_METHOD_NAME)) { isDecryptMethodPresent = true; }
            MethodVisitor methodVisitor = super.visitMethod(access, name, descriptor, signature, exceptions);
            return new LocalVariableAndStringVisitor(api, methodVisitor, className);
        }

        @Override
        public void visitEnd() {
            if (!isDecryptMethodPresent) { injectDecryptMethod(); }
            super.visitEnd();
        }

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
            mv.visitMaxs(0, 0);
            mv.visitEnd();
        }
    }

    static class LocalVariableAndStringVisitor extends MethodVisitor {
        private final String className;
        private final Map<String, String> localVariableMapping = new HashMap<>();

        public LocalVariableAndStringVisitor(int api, MethodVisitor methodVisitor, String className) { super(api, methodVisitor); this.className = className; }

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
            if ("this".equals(name)) { super.visitLocalVariable(name, descriptor, signature, start, end, index); return; }
            String newName = localVariableMapping.computeIfAbsent(name, k -> generateRandomName());
            super.visitLocalVariable(newName, descriptor, signature, start, end, index);
        }

        private String generateRandomName() {
            String chars = "Il"; int length = 15 + random.nextInt(6); StringBuilder sb = new StringBuilder();
            for (int i = 0; i < length; i++) { sb.append(chars.charAt(random.nextInt(chars.length()))); }
            return sb.toString();
        }

        private String xorEncrypt(String input) {
            char key = 'K'; StringBuilder output = new StringBuilder();
            for (int i = 0; i < input.length(); i++) { output.append((char) (input.charAt(i) ^ key)); }
            return output.toString();
        }
    }
}