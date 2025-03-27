import { Component, OnInit, EventEmitter, Output } from '@angular/core';
import { IonicModule } from '@ionic/angular';


@Component({
  selector: 'app-header',
  imports: [IonicModule],  // Ajoute cette ligne
  templateUrl: './header.component.html',
  styleUrls: ['./header.component.css']
})
export class HeaderComponent {

    @Output() profileMenuClicked = new EventEmitter<Event>();
  
    onProfileButtonClick(event: Event) {
      event.stopPropagation();
      this.profileMenuClicked.emit(event); // Émettre l'événement DOM
    }
  
}
