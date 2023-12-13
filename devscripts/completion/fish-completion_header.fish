function __fish_fdroid_package
    set files metadata/*.yml
    string replace -r 'metadata/(.*)\.yml' '$1' $files
end

function __fish_fdroid_apk_package
    set files "$argv[1]"/*_*.apk
    string replace -r '.*/(.*)_.*\.apk' '$1' $files
end

function __fish_fdroid_apk_files
    set files **.apk
    printf %s\n $files
end

function __fish_fdroid_scanner
    __fish_fdroid_package
    __fish_fdroid_apk_files
end
