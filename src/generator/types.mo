module {
    
    public type Generator<T> = {
      next : () -> T;
    };
}