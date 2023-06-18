package com.oscar.test.test;

import java.util.ArrayList;
import java.util.List;

public class FutureTest {
    public static void main(String[] args) throws InterruptedException {
        Thread.sleep(15000);
        List<Integer> list = new ArrayList<>();
        for(int i = 10_000_000; i < 19_000_000; i++) {
            list.add(Integer.valueOf(10_000_000 + i));
        }
        System.out.println(list.size());

        Thread.sleep(15000);

        list = null;
        System.gc();

        Thread.sleep(60000);
    }
}
