package com.test;

import java.lang.reflect.AccessibleObject;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Member;
import java.lang.reflect.Method;
import java.security.Permission;
import java.util.Map;

public class Main {

	public static void main(String[] args) {
		System.setSecurityManager(new MySecurityManager());
		System.out.println("Has security manager: " + (System.getSecurityManager() != null));
		long start = System.nanoTime();
		Field[] fields = disableSecurityManager();
		System.out.println("Time used: " + (System.nanoTime() - start));
		System.out.println("Has security manager: " + (System.getSecurityManager() != null));
		try {
			System.class.getDeclaredField("security");
			System.out.println("security field not filtered");
		} catch (NoSuchFieldException e) {
			System.out.println("security field filtered");
		}
		start = System.nanoTime();
		getFilterMap(Field.class).clear();
		System.out.println("Time used: " + (System.nanoTime() - start));
		try {
			System.class.getDeclaredField("security");
			System.out.println("security field not filtered");
		} catch (NoSuchFieldException e) {
			System.out.println("security field filtered");
		}
		start = System.nanoTime();
		setReflectionData(System.class, fields, null);
		System.out.println("Time used: " + (System.nanoTime() - start));
		try {
			System.class.getDeclaredField("security");
			System.out.println("security field not filtered");
		} catch (NoSuchFieldException e) {
			System.out.println("security field filtered");
		}
	}
	
	public static Field[] disableSecurityManager() {
		try {
			Method getDeclaredFields0M = Class.class.getDeclaredMethod("getDeclaredFields0", boolean.class);
			getDeclaredFields0M.setAccessible(true);
			Field[] fields = (Field[]) getDeclaredFields0M.invoke(System.class, false);
			Field securityField = null;
			for (Field field : fields) 
				if (field.getName().equals("security")) {
					securityField = field;
				}
			securityField.setAccessible(true);
			securityField.set(null, null);
			return fields;
		} catch (Throwable ex) {
			throw new UnsupportedOperationException(ex);
		}
	}
	
	@SuppressWarnings("unchecked")
	public static <T extends AccessibleObject & Member> Map<Class<?>, String[]> getFilterMap(Class<T> clazz) {
		if (Constructor.class.isAssignableFrom(clazz)) return null;
		try {
			Method getDeclaredFields0M = Class.class.getDeclaredMethod("getDeclaredFields0", boolean.class);
			getDeclaredFields0M.setAccessible(true);
			Field[] fields = (Field[]) getDeclaredFields0M.invoke(Class.forName("jdk.internal.reflect.Reflection"), false);
			Field field = null;
			for (Field f : fields) 
				if (f.getName().equals(clazz.getSimpleName().toLowerCase() + "FilterMap")) 
					field = f;
			fields = null;
			Method setAccessible0M = AccessibleObject.class.getDeclaredMethod("setAccessible0", boolean.class);
			setAccessible0M.setAccessible(true);
			setAccessible0M.invoke(field, true);
			return (Map<Class<?>, String[]>) field.get(null);
		} catch (Throwable ex) {
			throw new UnsupportedOperationException(ex);
		}
	}
	
	public static <T extends AccessibleObject & Member> void setReflectionData(Class<?> target, T[] data, Boolean inherit) {
		try {
			Method reflectionDataM = Class.class.getDeclaredMethod("reflectionData");
			reflectionDataM.setAccessible(true);
			Object reflectionData = reflectionDataM.invoke(target);
			Class<?> rdclass = reflectionData.getClass();
			String post = data.getClass().getComponentType().getSimpleName() + "s";
			Field field;
			if (inherit == null) 
				field = rdclass.getDeclaredField("declared" + post);
			else if (inherit) 
				field = rdclass.getDeclaredField("public" + post);
			else field = rdclass.getDeclaredField("publicDeclared" + post);
			field.setAccessible(true);
			field.set(reflectionData, data);
		} catch (Throwable ex) {
			throw new UnsupportedOperationException(ex);
		}
	}

	public static class MySecurityManager extends SecurityManager {
		
		@Override
		public void checkPermission(Permission permission) {
			if (permission.getName().equals("accessDeclaredMembers") || permission.getName().equals("suppressAccessChecks") || permission.getName().equals("getProtectionDomain") || permission.getName().contains("accessClassInPackage")) return;
			super.checkPermission(permission);
		}
		
	}
	
}
