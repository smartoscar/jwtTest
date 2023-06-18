package com.oscar.test;

import java.io.*;

public class MyLoader extends ClassLoader {
    private String classLoaderName;

    private final String fileSuffix = ".class";

    public MyLoader(String classLoaderName){
        super();
        this.classLoaderName = classLoaderName;
    }

    public MyLoader(ClassLoader parent, String classLoaderName) {
        super(parent);
        this.classLoaderName = classLoaderName;
    }

    @Override
    public String toString() {
        return "[" + classLoaderName + "]";
    }

    @Override
    protected Class findClass(String className){
        byte[] data = loadClassData(className);

        return this.defineClass(className, data, 0, data.length);
    }

    private byte[] loadClassData(String className) {
        byte[] data = null;
        InputStream is = null;
        ByteArrayOutputStream baos = null;

        try(InputStream inputStream = is = new FileInputStream(new File(className + fileSuffix))) {
            baos = new ByteArrayOutputStream();
            int ch;

            while(-1 != (ch = inputStream.read())) {
                baos.write(ch);
            }

            data = baos.toByteArray();
        } catch(Exception e) {
            e.printStackTrace();
        } finally {
            try {
                is.close();
                baos.close();
            } catch(IOException e) {
                e.printStackTrace();
            }
        }

        return data;
    }

    public static void main(String[] args) throws Exception {
        MyLoader myLoader = new MyLoader("MyClassLoader");
        Class<?> aClass = myLoader.loadClass("com.oscar.test.WebApplication");
        Object instance = aClass.getDeclaredConstructor().newInstance();
        System.out.println(instance);
    }

}
