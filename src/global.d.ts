/// <reference types="vite/client" />

type Public<T> = Pick<T, keyof T>;
