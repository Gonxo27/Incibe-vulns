package exceptions;

public abstract class AppException extends Exception {
    public AppException(String message) {
        super("[ERROR] " + message);
    }
}
